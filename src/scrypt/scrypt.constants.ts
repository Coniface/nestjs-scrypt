export const DEFAULT_COST = 16_384;
export const MIN_LOG2_COST = 1;
export const DEFAULT_LOG2_COST = Math.log2(DEFAULT_COST);
export const MAX_LOG2_COST = 62;

export const MIN_BLOCK_SIZE = 1;
export const DEFAULT_BLOCK_SIZE = 8;

export const MIN_PARALLELIZATION = 1;
export const DEFAULT_PARALLELIZATION = 1;

export const MIN_MAXMEM = 1024 * 1024;
export const DEFAULT_MAXMEM = 32 * 1024 * 1024;
export const MAX_MAXMEM = 2 ** 31 - 1;

export const MIN_MAXMEMFRAC = 0;
export const DEFAULT_MAXMEMFRAC = 0.5;
export const MAX_MAXMEMFRAC = 0.5;

export const DEFAULT_MAXTIME = 0.1;

export const DEFAULT_SALT_LENGTH = 32;

export const DEFAULT_KEY_LENGTH = 64;
