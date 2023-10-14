import { plainToInstance } from 'class-transformer';
import { Buffer } from 'node:buffer';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { ScryptModuleParams } from './scrypt.module-params';

export class BufferedKeyBuilder {
  readonly algorithm: Buffer;
  readonly version: Buffer;
  readonly cost: Buffer;
  readonly blockSize: Buffer;
  readonly parallelization: Buffer;
  readonly salt: Buffer;
  readonly paramsBlock: Buffer;
  readonly paramsChecksum: Buffer;
  readonly header: Buffer;
  readonly hmacHash: Buffer;

  private readonly buffer: Buffer;

  private constructor(buffer?: Buffer) {
    this.buffer = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(96);

    this.algorithm = this.buffer.subarray(0, 6);
    this.version = this.buffer.subarray(6, 7);
    this.cost = this.buffer.subarray(7, 8);
    this.blockSize = this.buffer.subarray(8, 12);
    this.parallelization = this.buffer.subarray(12, 16);
    this.salt = this.buffer.subarray(16, 48);
    this.paramsBlock = this.buffer.subarray(0, 48);
    this.paramsChecksum = this.buffer.subarray(48, 64);
    this.header = this.buffer.subarray(0, 64);
    this.hmacHash = this.buffer.subarray(64, 96);
  }

  static create() {
    const wrapper = new BufferedKeyBuilder();
    return wrapper;
  }

  static fromBuffer(key: Buffer) {
    if (key.byteLength < 96) {
      throw new Error(`key should be 96 bytes, got ${key.byteLength}`);
    }
    const wrapper = new BufferedKeyBuilder(key);
    return wrapper;
  }

  build() {
    return this.buffer;
  }

  readAlgorithm() {
    return this.algorithm;
  }

  writeAlgorithm() {
    this.algorithm.write('scrypt');
    return this;
  }

  readCost() {
    return this.cost.readUint8();
  }

  writeCost(cost: number) {
    this.cost.writeUint8(cost);
    return this;
  }

  readBlockSize() {
    return this.blockSize.readUint32BE();
  }

  writeBlockSize(blockSize: number) {
    this.blockSize.writeUint32BE(blockSize);
    return this;
  }

  readParallelization() {
    return this.parallelization.readUint32BE();
  }

  writeParallelization(parallelization: number) {
    this.parallelization.writeUint32BE(parallelization);
    return this;
  }

  readSalt() {
    return this.salt;
  }

  writeSalt(salt: Buffer) {
    salt.copy(this.salt);
    return this;
  }

  readScryptModuleParams(): ScryptModuleParams {
    return plainToInstance(ScryptModuleParams, {
      cost: this.readCost(),
      blockSize: this.readBlockSize(),
      parallelization: this.readParallelization(),
    });
  }

  readParamsChecksum() {
    return this.paramsChecksum;
  }

  writeParamsChecksum() {
    createHash('sha256')
      .update(this.paramsBlock)
      .digest()
      .copy(this.paramsChecksum, 0, 0, 16);
    return this;
  }

  verifyParamsChecksum() {
    const paramsChecksum = createHash('sha256')
      .update(this.paramsBlock)
      .digest()
      .subarray(0, 16);

    return timingSafeEqual(paramsChecksum, this.paramsChecksum);
  }

  readHmacHash() {
    return this.hmacHash;
  }

  writeHmacHash(hash: Buffer) {
    createHmac('sha256', hash.subarray(32))
      .update(this.header)
      .digest()
      .copy(this.hmacHash);
    return this;
  }
}
