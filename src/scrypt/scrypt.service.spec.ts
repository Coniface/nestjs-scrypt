import { Test, TestingModule } from '@nestjs/testing';
import { Buffer } from 'node:buffer';
import {
  DEFAULT_BLOCK_SIZE,
  DEFAULT_LOG2_COST,
  DEFAULT_MAXMEM,
  DEFAULT_MAXTIME,
  DEFAULT_PARALLELIZATION,
} from './scrypt.constants';
import { MODULE_OPTIONS_TOKEN } from './scrypt.module-definition';
import { ScryptModuleOptions } from './scrypt.module-options';
import { ScryptModuleParams } from './scrypt.module-params';
import { ScryptService } from './scrypt.service';

describe('ScryptService', () => {
  let service: ScryptService;
  const scryptParams: ScryptModuleOptions = {
    cost: DEFAULT_LOG2_COST,
    blockSize: DEFAULT_BLOCK_SIZE,
    parallelization: DEFAULT_PARALLELIZATION,
    maxMemory: DEFAULT_MAXMEM,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: MODULE_OPTIONS_TOKEN, useValue: scryptParams },
        ScryptService,
      ],
    }).compile();

    service = module.get<ScryptService>(ScryptService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should compute best Scrypt params on ModuleInit', async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: MODULE_OPTIONS_TOKEN, useValue: {} },
        ScryptService,
      ],
    }).compile();

    service = module.get<ScryptService>(ScryptService);
    await service.onModuleInit();
    const serviceParams: ScryptModuleParams = (service as any).params;

    expect(serviceParams.maxTime).toBe(DEFAULT_MAXTIME);
    expect(serviceParams.cost).toBeGreaterThan(0);
    expect(serviceParams.blockSize).toBeGreaterThan(0);
    expect(serviceParams.parallelization).toBeGreaterThan(0);
    expect(serviceParams.maxMemory).toBeGreaterThan(0);
  });

  it('should derive a passphrase into a key', async () => {
    const passphrase = '58C17E';
    const key = await service.kdf(passphrase);

    expect(Buffer.isBuffer(key)).toBe(true);
  });

  it('should show derivation parameters from a derived key', async () => {
    const passphrase = '61n';
    const key = await service.kdf(passphrase);

    const params = service.viewParams(key);

    expect(params.log2N).toBe(scryptParams.cost);
    expect(params.r).toBe(scryptParams.blockSize);
    expect(params.p).toBe(scryptParams.parallelization);
  });

  describe('verify', () => {
    it('should return true if a passphrase matches a derived key', async () => {
      const passphrase = 'de0S3T8l';
      const key = await service.kdf(passphrase);

      const result = await service.verify(key, passphrase);

      expect(result).toBe(true);
    });

    it('should return false if a passphrase does not match a derived key', async () => {
      const passphrase = 'j73Z9Zuc';
      const wrongPassphrase = 'hhBigop';
      const key = await service.kdf(passphrase);

      const result = await service.verify(key, wrongPassphrase);

      expect(result).toBe(false);
    });
  });
});
