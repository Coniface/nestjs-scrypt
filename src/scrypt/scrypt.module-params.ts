import { MAX_MAXMEM } from './scrypt.constants';
import { ScryptModuleOptions } from './scrypt.module-options';
import { ScryptNodeParams, ScryptParams } from './scrypt.params';

export class ScryptModuleParams extends ScryptModuleOptions {
  declare cost: number;
  declare blockSize: number;
  declare parallelization: number;
  declare maxMemory: number;
  declare maxMemoryFrac: number;
  declare maxTime: number;

  toParams(): ScryptParams {
    return {
      log2N: this.cost,
      r: this.blockSize,
      p: this.parallelization,
    };
  }

  toNodeParams(): ScryptNodeParams {
    return {
      ...(this.cost && { N: 2 ** this.cost }),
      ...(this.blockSize && { r: this.blockSize }),
      ...(this.parallelization && { p: this.parallelization }),
      maxmem: this.maxMemory || MAX_MAXMEM,
    };
  }
}
