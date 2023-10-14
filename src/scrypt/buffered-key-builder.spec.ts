import { Buffer } from 'node:buffer';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { BufferedKeyBuilder } from './buffered-key-builder';
import { ScryptModuleParams } from './scrypt.module-params';
import { ScryptNodeParams } from './scrypt.params';

jest.mock('node:crypto', () => ({
  createHash: jest.fn(),
  createHmac: jest.fn(),
  timingSafeEqual: jest.fn(),
}));

const createHashMock = jest.mocked(createHash);
const createHmacMock = jest.mocked(createHmac);
const timingSafeEqualMock = jest.mocked(timingSafeEqual);

describe('BufferedKeyBuilder', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should build a buffer of the right size', () => {
    const buffer = BufferedKeyBuilder.create().build();

    expect(Buffer.isBuffer(buffer)).toBe(true);
    expect(buffer.length).toBe(96);
    expect(buffer.byteLength).toBe(96);
  });

  it('should write "scrypt" on the buffer', () => {
    const builder = BufferedKeyBuilder.create().writeAlgorithm();
    const buffer = builder.build();
    const expected = Buffer.from('scrypt');

    expect(builder.algorithm.length).toBe(6);
    expect(expected.compare(builder.algorithm)).toBe(0);
    expect(expected.compare(buffer.subarray(0, 6))).toBe(0);
    expect(builder.readAlgorithm().toString()).toBe('scrypt');
  });

  it('should write the version "0" of the algorithm on the buffer', () => {
    const builder = BufferedKeyBuilder.create();
    const buffer = builder.build();
    const expected = Buffer.alloc(1);

    expect(builder.version.length).toBe(1);
    expect(expected.compare(builder.version)).toBe(0);
    expect(expected.compare(buffer.subarray(6, 7))).toBe(0);
  });

  it('should write the log2N on the buffer', () => {
    const logN = 25;
    const builder = BufferedKeyBuilder.create().writeCost(logN);
    const buffer = builder.build();
    const expected = Buffer.alloc(1);

    expected.writeUint8(logN);

    expect(builder.cost.length).toBe(1);
    expect(expected.compare(builder.cost)).toBe(0);
    expect(expected.compare(buffer.subarray(7, 8))).toBe(0);
    expect(builder.readCost()).toBe(logN);
  });

  it('should write the blockSize on the buffer', () => {
    const blockSize = 10;
    const builder = BufferedKeyBuilder.create().writeBlockSize(blockSize);
    const buffer = builder.build();
    const expected = Buffer.alloc(4);

    expected.writeUInt32BE(blockSize);

    expect(builder.blockSize.length).toBe(4);
    expect(expected.compare(builder.blockSize)).toBe(0);
    expect(expected.compare(buffer.subarray(8, 12))).toBe(0);
    expect(builder.readBlockSize()).toBe(blockSize);
  });

  it('should write the parallelization on the buffer', () => {
    const parallelization = 8;
    const builder =
      BufferedKeyBuilder.create().writeParallelization(parallelization);
    const buffer = builder.build();
    const expected = Buffer.alloc(4);

    expected.writeUInt32BE(parallelization);

    expect(builder.parallelization.length).toBe(4);
    expect(expected.compare(builder.parallelization)).toBe(0);
    expect(expected.compare(buffer.subarray(12, 16))).toBe(0);
    expect(builder.readParallelization()).toBe(parallelization);
  });

  it('should read scrypt params', () => {
    const log2Cost = 15;
    const blockSize = 12;
    const parallelization = 4;
    const builder = BufferedKeyBuilder.create()
      .writeCost(log2Cost)
      .writeBlockSize(blockSize)
      .writeParallelization(parallelization);
    const params = builder.readScryptModuleParams();
    const expected: ScryptNodeParams = {
      N: 2 ** log2Cost,
      r: blockSize,
      p: parallelization,
    };

    expect(params).toBeInstanceOf(ScryptModuleParams);
    expect(params.toNodeParams()).toEqual(expected);
  });

  it('should write the salt on the buffer', () => {
    const salt = Buffer.from('pH2ZZFj0MH5te3vI10s5KAjiOlc5fMrX');
    const builder = BufferedKeyBuilder.create().writeSalt(salt);
    const buffer = builder.build();
    const expected = Buffer.alloc(32);

    salt.copy(expected);

    expect(builder.salt.length).toBe(32);
    expect(expected.compare(builder.salt)).toBe(0);
    expect(expected.compare(buffer.subarray(16, 48))).toBe(0);
    expect(builder.readSalt().toString()).toBe(salt.toString());
  });

  it('should write a checksum of the params and salt on the buffer', () => {
    const sha256 = Buffer.from('bLTDuvBPflHzLYlkTB6vk3OeFQILUC6k');
    const expected = sha256.subarray(0, 16);
    const mockedHash = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue(sha256),
    };
    createHashMock.mockImplementation(() => mockedHash as any);

    const builder = BufferedKeyBuilder.create().writeParamsChecksum();
    const buffer = builder.build();

    expect(createHashMock).toHaveBeenCalledTimes(1);
    expect(createHashMock).toHaveBeenCalledWith('sha256');
    expect(mockedHash.update).toHaveBeenCalledTimes(1);
    expect(mockedHash.update).toHaveBeenCalledWith(builder.paramsBlock);
    expect(mockedHash.digest).toHaveBeenCalledTimes(1);
    expect(builder.paramsChecksum.length).toBe(16);
    expect(expected.compare(builder.paramsChecksum)).toBe(0);
    expect(expected.compare(buffer.subarray(48, 64))).toBe(0);
    expect(builder.readParamsChecksum().toString()).toBe(expected.toString());
  });

  it('should verify params checksums against itself', () => {
    const sha256 = Buffer.from('CPDSSxG80CouYWRPWdyv6cVFl7LiCeKo');
    const expected = sha256.subarray(0, 16);
    const mockedHash = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue(sha256),
    };
    createHashMock.mockImplementation(() => mockedHash as any);
    timingSafeEqualMock.mockImplementationOnce(() => true);

    const builder = BufferedKeyBuilder.create();
    sha256.copy(builder.paramsChecksum, 0, 0, 16);
    const result = builder.verifyParamsChecksum();

    expect(result).toBe(true);
    expect(timingSafeEqualMock).toHaveBeenCalledTimes(1);
    expect(timingSafeEqualMock).toHaveBeenCalledWith(
      sha256.subarray(0, 16),
      expected,
    );
    expect(createHashMock).toHaveBeenCalledTimes(1);
    expect(createHashMock).toHaveBeenCalledWith('sha256');
    expect(mockedHash.update).toHaveBeenCalledTimes(1);
    expect(mockedHash.update).toHaveBeenCalledWith(builder.paramsBlock);
    expect(mockedHash.digest).toHaveBeenCalledTimes(1);
    expect(builder.paramsChecksum.length).toBe(16);
    expect(expected.compare(builder.paramsChecksum)).toBe(0);
    expect(builder.readParamsChecksum().toString()).toBe(expected.toString());
  });

  it('should write the hmac hash on the buffer', () => {
    const sha256 = Buffer.from(
      'g2GKYpQv5cZcJ7Ky62zme7TCpHhUsOHFhab1d8wykRXTkiIMCRP84UHXOFrgntN0',
    );
    const expected = sha256.subarray(32);
    const mockedHmac = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValueOnce(expected),
    };
    createHmacMock.mockImplementationOnce(() => mockedHmac as any);

    const builder = BufferedKeyBuilder.create().writeHmacHash(sha256);
    const buffer = builder.build();

    expect(createHmacMock).toHaveBeenCalledTimes(1);
    expect(createHmacMock).toHaveBeenCalledWith('sha256', expected);
    expect(mockedHmac.update).toHaveBeenCalledTimes(1);
    expect(mockedHmac.update).toHaveBeenCalledWith(builder.header);
    expect(mockedHmac.digest).toHaveBeenCalledTimes(1);
    expect(builder.hmacHash.length).toBe(32);
    expect(expected.compare(builder.hmacHash)).toBe(0);
    expect(expected.compare(buffer.subarray(64, 96))).toBe(0);
    expect(builder.readHmacHash().toString()).toBe(expected.toString());
  });
});
