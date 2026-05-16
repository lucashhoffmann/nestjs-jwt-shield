import type { DynamicModule, InjectionToken } from '@nestjs/common';
import type { z } from 'zod';
import type { JwtShieldDefaultClaims } from './jwt-shield-claims';

export type JwtShieldAlgorithm = 'HS256';

export type JwtShieldDuration =
  | number
  | `${number}s`
  | `${number}m`
  | `${number}h`;

export interface JwtShieldModuleOptions<
  TClaims extends object = JwtShieldDefaultClaims
> {
  issuer: string;
  audience: string | string[];
  algorithm: JwtShieldAlgorithm;
  secret: string;
  accessTokenTtl?: JwtShieldDuration;
  maxAccessTokenTtl?: JwtShieldDuration;
  strict?: boolean;
  isGlobal?: boolean;
  useGlobalGuard?: boolean;
  claimsSchema?: z.ZodType<TClaims>;
  clockTolerance?: JwtShieldDuration;
}

export interface JwtShieldModuleAsyncOptions<
  TClaims extends object = JwtShieldDefaultClaims
> {
  imports?: DynamicModule['imports'];
  inject?: InjectionToken[];
  isGlobal?: boolean;
  useGlobalGuard?: boolean;
  useFactory: (
    ...args: unknown[]
  ) => JwtShieldModuleOptions<TClaims> | Promise<JwtShieldModuleOptions<TClaims>>;
}

export interface JwtShieldResolvedOptions<
  TClaims extends object = JwtShieldDefaultClaims
> {
  issuer: string;
  audience: string | string[];
  algorithm: JwtShieldAlgorithm;
  secret: string;
  accessTokenTtlSeconds: number;
  maxAccessTokenTtlSeconds: number;
  strict: boolean;
  isGlobal: boolean;
  useGlobalGuard: boolean;
  clockToleranceSeconds: number;
  claimsSchema?: z.ZodType<TClaims>;
}

export interface JwtShieldSignAccessTokenOptions {
  accessTokenTtl?: JwtShieldDuration;
}
