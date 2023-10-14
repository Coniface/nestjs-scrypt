import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { plainToClass, plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { Buffer } from 'node:buffer';
import { randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import * as os from 'node:os';
import { performance } from 'node:perf_hooks';
import { BufferedKeyBuilder } from './buffered-key-builder';
import {
  DEFAULT_BLOCK_SIZE,
  DEFAULT_COST,
  DEFAULT_KEY_LENGTH,
  DEFAULT_MAXMEMFRAC,
  DEFAULT_MAXTIME,
  DEFAULT_SALT_LENGTH,
  MAX_LOG2_COST,
  MAX_MAXMEMFRAC,
  MIN_MAXMEM,
} from './scrypt.constants';
import { SCRYPT_OPTIONS_TOKEN } from './scrypt.module-definition';
import { ScryptModuleOptions } from './scrypt.module-options';
import { ScryptModuleParams } from './scrypt.module-params';
import { ScryptNodeParams, ScryptParams } from './scrypt.params';

@Injectable()
export class ScryptService implements OnModuleInit {
  private readonly logger = new Logger(ScryptService.name);
  private readonly params: ScryptModuleParams;

  constructor(
    @Inject(SCRYPT_OPTIONS_TOKEN)
    plainOptions: ScryptModuleOptions,
  ) {
    this.params = plainToClass(ScryptModuleParams, plainOptions);
    const validationErrors = validateSync(this.params);
    if (validationErrors.length > 0) {
      const parsedConstraints = validationErrors.reduce(
        (errors, error) => errors.concat(Object.values(error.constraints)),
        [],
      );
      throw new Error(
        `Invalid ScryptModuleOptions:\n\t- ${parsedConstraints.join('\n\t- ')}`,
      );
    }
  }

  /**
   * Compute missing scrypt parameters.
   */
  async onModuleInit() {
    if (
      !Number.isInteger(this.params.cost) ||
      !Number.isInteger(this.params.blockSize) ||
      !Number.isInteger(this.params.parallelization) ||
      !Number.isInteger(this.params.maxMemory)
    ) {
      this.params.maxTime ??= DEFAULT_MAXTIME;

      const computedParams = this.computeScryptParams(
        this.params.maxTime,
        this.params.maxMemory,
        this.params.maxMemoryFrac,
      );

      this.params.cost ??= computedParams.cost;
      this.params.blockSize ??= computedParams.blockSize;
      this.params.parallelization ??= computedParams.parallelization;
      this.params.maxMemory ??= computedParams.maxMemory;
    }

    if (
      128 * this.params.cost ** 2 * this.params.blockSize >
      this.params.maxMemory
    ) {
      this.logger.warn(
        'Possible error in Scrypt params (128 * N * r > maxmem)',
      );
    }
  }

  /**
   * Derives a key from a passphrase.
   * Returns a Buffer which can be stored as-is or encoded as a string.
   *
   * 96 bytes long buffer equals a 128 characters long base64 string.
   * @length 96 bytes
   */
  async kdf(passphrase: string | ArrayBufferView): Promise<Buffer> {
    // Prepare salt
    const salt = await this.generateSalt();

    return this.deriveKey(passphrase, salt, this.params);
  }

  /**
   * Checks that the key can be derived from passphrase.
   */
  async verify(
    key: Uint8Array,
    passphrase: string | ArrayBufferView,
  ): Promise<boolean> {
    // Parse key
    const bufferedKey = Buffer.from(key);
    const keyReader = BufferedKeyBuilder.fromBuffer(bufferedKey);
    if (!keyReader.verifyParamsChecksum()) {
      return false;
    }

    // Parse passphrase
    const derivedKey = await this.deriveKey(
      passphrase,
      keyReader.readSalt(),
      keyReader.readScryptModuleParams(),
    );

    return timingSafeEqual(bufferedKey, derivedKey);
  }

  /**
   * Extracts derivation parameters from an existing key.
   */
  viewParams(key: Uint8Array): ScryptParams {
    const bufferedKey = Buffer.from(key);
    const builder = BufferedKeyBuilder.fromBuffer(bufferedKey);
    return builder.readScryptModuleParams().toParams();
  }

  private async deriveKey(
    passphrase: string | ArrayBufferView,
    salt: Buffer,
    params: ScryptModuleParams,
  ): Promise<Buffer> {
    // Parse passphrase
    const bufferedPassphrase =
      typeof passphrase === 'string'
        ? Buffer.from(passphrase)
        : Buffer.from(passphrase.buffer);

    // Prepare params and result buffer
    const bufferedKey = BufferedKeyBuilder.create()
      .writeAlgorithm()
      .writeCost(params.cost)
      .writeBlockSize(params.blockSize)
      .writeParallelization(params.parallelization);

    // Write salt to result buffer and compute params checksum
    bufferedKey.writeSalt(salt).writeParamsChecksum();

    // Hash passphrase
    const hash = await this.generateHash(
      bufferedPassphrase,
      salt,
      DEFAULT_KEY_LENGTH,
      params.toNodeParams(),
    );

    // Sign and write hash to result buffer
    bufferedKey.writeHmacHash(hash);

    return bufferedKey.build();
  }

  private generateSalt(size: number = DEFAULT_SALT_LENGTH): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      randomBytes(size, (err, salt) => (err ? reject(err) : resolve(salt)));
    });
  }

  private generateHash(
    passphrase: Buffer,
    salt: Buffer,
    keyLength: number,
    params: ScryptNodeParams,
  ): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      scrypt(passphrase, salt, keyLength, params, (err, derivedKey) =>
        err ? reject(err) : resolve(derivedKey),
      );
    });
  }

  private computeScryptParams(
    maxTime: number,
    maxMemory: number,
    maxMemoryFrac: number,
  ): ScryptModuleParams {
    const maxMem = maxMemory || os.totalmem();
    const maxMemFrac = Math.min(
      maxMemoryFrac || DEFAULT_MAXMEMFRAC,
      MAX_MAXMEMFRAC,
    );

    // 1MB <= memLimit <= fraction of memory <= maxMem
    const physicalMemory = os.totalmem();
    const memLimit = Math.max(
      Math.min(physicalMemory * maxMemFrac, maxMem),
      MIN_MAXMEM,
    );

    // Measuring scrypt computation time
    let i = 0;
    const start = performance.now();
    while (performance.now() - start < 10) {
      scryptSync('', '', DEFAULT_KEY_LENGTH, { N: 128, r: 1, p: 1 });
      i += 512; // salsa20/8 core called 512 times
    }
    const duration = (performance.now() - start) / 1000; // in seconds
    const operationPerSecond = i / duration;

    // Allow a minimum of 2^14 salsa20/8 cores
    const opsLimit = Math.max(operationPerSecond * maxTime, DEFAULT_COST);
    const r = DEFAULT_BLOCK_SIZE;

    // Memory limit requires that 128·N·r <= memLimit
    // CPU limit requires that 4·N·r·p <= opsLimit
    // If (opsLimit < memLimit / 32), opsLimit imposes the stronger limit on N

    let p = 1;
    let logN = 0;
    if (opsLimit < memLimit / 32) {
      // Keep p = 1 & determine N based on CPU limit
      const maxN = opsLimit / (r * 4);
      while (1 << logN <= maxN / 2 && logN <= MAX_LOG2_COST) logN++;
    } else {
      // Set N based on the memory limit
      const maxN = memLimit / (r * 128);
      while (1 << logN <= maxN / 2 && logN < MAX_LOG2_COST) logN++;

      // Choose p based on the CPU limit
      const maxRp = Math.min(opsLimit / 4 / (1 << logN), 0x3fffffff);
      p = Math.round(maxRp / r);
    }

    return plainToInstance(ScryptModuleParams, {
      cost: logN,
      blockSize: r,
      parallelization: p,
      maxMemory: memLimit,
    });
  }
}
