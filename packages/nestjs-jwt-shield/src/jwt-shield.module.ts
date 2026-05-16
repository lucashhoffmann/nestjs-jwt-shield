import { DynamicModule, Module, Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JWT_SHIELD_OPTIONS } from './jwt-shield.constants';
import { JwtShieldGuard } from './jwt-shield.guard';
import { JwtShieldService } from './jwt-shield.service';
import type { JwtShieldDefaultClaims } from './types/jwt-shield-claims';
import type {
  JwtShieldModuleAsyncOptions,
  JwtShieldModuleOptions
} from './types/jwt-shield-options';
import { resolveJwtShieldOptions } from './utils/assert-secure-config';

@Module({})
export class JwtShieldModule {
  static register<TClaims extends object = JwtShieldDefaultClaims>(
    options: JwtShieldModuleOptions<TClaims>
  ): DynamicModule {
    const resolvedOptions = resolveJwtShieldOptions(options);

    return {
      module: JwtShieldModule,
      global: resolvedOptions.isGlobal,
      providers: [
        {
          provide: JWT_SHIELD_OPTIONS,
          useValue: resolvedOptions
        },
        JwtShieldService,
        JwtShieldGuard,
        ...createGlobalGuardProvider(resolvedOptions.useGlobalGuard)
      ],
      exports: [JwtShieldService, JwtShieldGuard]
    };
  }

  static registerAsync<TClaims extends object = JwtShieldDefaultClaims>(
    options: JwtShieldModuleAsyncOptions<TClaims>
  ): DynamicModule {
    return {
      module: JwtShieldModule,
      global: options.isGlobal ?? false,
      imports: options.imports ?? [],
      providers: [
        {
          provide: JWT_SHIELD_OPTIONS,
          useFactory: async (...args: unknown[]) =>
            resolveJwtShieldOptions(await options.useFactory(...args)),
          inject: options.inject ?? []
        },
        JwtShieldService,
        JwtShieldGuard,
        ...createGlobalGuardProvider(options.useGlobalGuard ?? false)
      ],
      exports: [JwtShieldService, JwtShieldGuard]
    };
  }
}

function createGlobalGuardProvider(useGlobalGuard: boolean): Provider[] {
  if (!useGlobalGuard) {
    return [];
  }

  return [
    {
      provide: APP_GUARD,
      useExisting: JwtShieldGuard
    }
  ];
}
