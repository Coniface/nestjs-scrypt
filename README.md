# nestjs-scrypt

A NestJS module providing a wrapper around NodeJS `crypto.scrypt` function.

## How to use

Install it using your favorite packet manager:

```shell
pnpm i @coniface/nestjs-scrypt
```

```shell
yarn add @coniface/nestjs-scrypt
```

```shell
npm i @coniface/nestjs-scrypt
```

Declare the module in your NestJS App declaration:

```typescript
import { ScryptModule } from '@coniface/nestjs-scrypt';

@Module({
  imports: [
    ScryptModule.forRoot({}),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

You can also pass specific Scrypt params on module creation.

Then use the ScryptService to hash and verify passphrases:

```typescript
import { ScryptService } from '@coniface/nestjs-scrypt';

@Injectable()
export class UsersService {
  constructor(
    private readonly scryptService: ScryptService,
  ) {}

  private async derivePassphrase(passphrase: string): Promise<Buffer> {
    const key = await this.scryptService.kdf(passphrase);
    return key;
  }

  private async verifyPassphrase(key: Buffer, passphrase: string): Promise<boolean> {
    const result = await this.scryptService.verify(key, passphrase);
    return result;
  }
}
```

## How it works

Based on [scrypt](https://github.com/Tarsnap/scrypt) utility developed for Tarsnap.

### Parameters

Scrypt computation parameters are:

- `cost` CPU/memory cost parameter. Must be a power of two greater than one.
- `blockSize` Block size parameter.
- `parallelization` Parallelization parameter.
- `maxMemory` Memory upper bound.

This module also accepts:

- `maxMemoryFrac` Maximum fraction of available RAM scrypt should use for computing.
- `maxTime` Maximum time in seconds scrypt should spend computing the derived key.

By default, the module will be called with:

```typescript
import { ScryptModule } from '@coniface/nestjs-scrypt';

@Module({
  imports: [
    // Will compute cost, blockSize and parallelization for a scrypt computation of 100ms
    ScryptModule.forRoot({
      maxTime: 0.1,
      maxMemory: os.totalmem(),
      maxMemoryFrac: 0.5,
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

If you want to increase computation complexity to 1s, you could create the module like so:

```typescript
import { ScryptModule } from '@coniface/nestjs-scrypt';

@Module({
  imports: [
    // Will compute cost, blockSize and parallelization for a scrypt computation of 1s
    ScryptModule.forRoot({
      maxTime: 1,
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

You could also manually specify parameters that fit your system and avoid the initial parameters computation:

```typescript
import { ScryptModule } from '@coniface/nestjs-scrypt';

@Module({
  imports: [
    // Manually define scrypt parameters, no initial computation
    ScryptModule.forRoot({
      cost: 14,
      blockSize: 8,
      parallelization: 1,
      maxMemory: 32 * 1024 * 1024,
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

### Module creation

If no scrypt params are explicitly defined, the module will compute the best params for a computation time of 0.1
seconds.
If a `maxTime` is defined, the module will compute the best params for a computation time matching this `maxTime`.
