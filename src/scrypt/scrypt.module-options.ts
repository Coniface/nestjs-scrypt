import {
  IsInt,
  IsNumber,
  IsOptional,
  IsPositive,
  Max,
  Min,
} from 'class-validator';
import {
  MAX_LOG2_COST,
  MAX_MAXMEM,
  MAX_MAXMEMFRAC,
  MIN_BLOCK_SIZE,
  MIN_LOG2_COST,
  MIN_MAXMEM,
  MIN_PARALLELIZATION,
} from './scrypt.constants';

/**
 * The options of the scrypt key derivation function.
 *
 * If not specified, the module will estimate the best values for the current
 * hardware on first run.
 */
export class ScryptModuleOptions {
  /**
   * CPU/memory cost parameter.
   * log2 value of the node `cost` parameter.
   * @alias N
   * @default 14
   * @min 1
   * @max 30
   */
  @IsOptional()
  @IsInt()
  @Min(MIN_LOG2_COST)
  @Max(MAX_LOG2_COST)
  cost?: number;

  /**
   * Block size parameter.
   * @alias r
   * @default 8
   * @min 1
   */
  @IsOptional()
  @IsInt()
  @Min(MIN_BLOCK_SIZE)
  blockSize?: number;

  /**
   * Parallelization parameter.
   * @alias p
   * @default 1
   * @min 1
   */
  @IsOptional()
  @IsInt()
  @Min(MIN_PARALLELIZATION)
  parallelization?: number;

  /**
   * Memory upper bound.
   * @default 32 * 1024 * 1024
   * @min 128
   * @max 2 ** 31 - 1
   * @throw approximately when `128 * cost * blockSize > maxmem`
   */
  @IsOptional()
  @IsInt()
  @Min(MIN_MAXMEM)
  @Max(MAX_MAXMEM)
  maxMemory?: number;

  /**
   * Maximum fraction of available RAM scrypt should use for computing
   * the derived key.
   * @default 0.5
   * @min 0
   * @max 0.5
   */
  @IsOptional()
  @IsNumber()
  @IsPositive()
  @Max(MAX_MAXMEMFRAC)
  maxMemoryFrac?: number;

  /**
   * Maximum time in seconds scrypt should spend computing the derived key.
   * @default 0.1
   */
  @IsOptional()
  @IsNumber()
  @IsPositive()
  maxTime?: number;
}
