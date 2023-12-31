import { Module } from '@nestjs/common';
import { ConfigurableScryptModule } from './scrypt.module-definition';
import { ScryptService } from './scrypt.service';

/**
 * Provides a ScryptService to help using Node's native scrypt implementation.
 */
@Module({
  providers: [ScryptService],
  exports: [ScryptService],
})
export class ScryptModule extends ConfigurableScryptModule {}
