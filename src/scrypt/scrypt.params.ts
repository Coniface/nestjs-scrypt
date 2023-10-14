export interface ScryptParams {
  log2N: number;
  r: number;
  p: number;
}

export interface ScryptNodeParams {
  N: number;
  r: number;
  p: number;
  maxmem?: number;
}
