import { ConfigurableModuleBuilder } from '@nestjs/common';
import { ScryptModuleOptions } from './scrypt.module-options';

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<ScryptModuleOptions>()
    .setClassMethodName('forRoot')
    .setFactoryMethodName('createScryptOptions')
    .build();
