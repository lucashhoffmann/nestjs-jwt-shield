import { JwtShieldInsecureConfigError, JwtShieldInvalidClaimsError } from '../errors/jwt-shield.errors';
import type { JwtShieldDefaultClaims } from '../types/jwt-shield-claims';
import type {
  JwtShieldDuration,
  JwtShieldModuleOptions,
  JwtShieldResolvedOptions
} from '../types/jwt-shield-options';
import { durationToSeconds } from './time';

export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const DEFAULT_MAX_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
export const MIN_HS256_SECRET_BYTES = 32;

const SENSITIVE_CLAIM_KEYS = new Set([
  'password',
  'secret',
  'refreshtoken',
  'apikey',
  'privatekey'
]);

export function assertSecureConfig<
  TClaims extends object = JwtShieldDefaultClaims
>(options: JwtShieldModuleOptions<TClaims>): void {
  resolveJwtShieldOptions(options);
}

export function resolveJwtShieldOptions<
  TClaims extends object = JwtShieldDefaultClaims
>(options: JwtShieldModuleOptions<TClaims>): JwtShieldResolvedOptions<TClaims> {
  if (!isRecord(options)) {
    throw new JwtShieldInsecureConfigError('JwtShieldModule options are required.');
  }

  const strict = options.strict ?? true;
  const issuer = normalizeNonEmptyString(options.issuer, 'issuer');
  const audience = normalizeAudience(options.audience);

  if (options.algorithm !== 'HS256') {
    throw new JwtShieldInsecureConfigError(
      'algorithm must be configured explicitly as "HS256" in this MVP.'
    );
  }

  const secret = normalizeNonEmptyString(options.secret, 'secret');
  const secretBytes = new TextEncoder().encode(secret).byteLength;

  if (secretBytes < MIN_HS256_SECRET_BYTES) {
    throw new JwtShieldInsecureConfigError(
      `HS256 secret must be at least ${MIN_HS256_SECRET_BYTES} bytes. Use a high-entropy secret from a secret manager.`
    );
  }

  const accessTokenTtlSeconds = readDuration(
    options.accessTokenTtl,
    DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
    'accessTokenTtl'
  );
  const maxAccessTokenTtlSeconds = readDuration(
    options.maxAccessTokenTtl,
    DEFAULT_MAX_ACCESS_TOKEN_TTL_SECONDS,
    'maxAccessTokenTtl'
  );
  const clockToleranceSeconds = readDuration(
    options.clockTolerance,
    DEFAULT_CLOCK_TOLERANCE_SECONDS,
    'clockTolerance'
  );

  if (strict && maxAccessTokenTtlSeconds > DEFAULT_MAX_ACCESS_TOKEN_TTL_SECONDS) {
    throw new JwtShieldInsecureConfigError(
      'strict mode does not allow maxAccessTokenTtl greater than 1h.'
    );
  }

  assertAccessTokenTtlWithinLimit(
    accessTokenTtlSeconds,
    maxAccessTokenTtlSeconds,
    'accessTokenTtl'
  );

  const resolvedOptions = {
    issuer,
    audience,
    algorithm: options.algorithm,
    secret,
    accessTokenTtlSeconds,
    maxAccessTokenTtlSeconds,
    strict,
    isGlobal: options.isGlobal ?? false,
    useGlobalGuard: options.useGlobalGuard ?? false,
    clockToleranceSeconds
  } satisfies JwtShieldResolvedOptions<TClaims>;

  if (options.claimsSchema) {
    return {
      ...resolvedOptions,
      claimsSchema: options.claimsSchema
    };
  }

  return resolvedOptions;
}

export function readOptionalDuration(
  duration: JwtShieldDuration | undefined,
  fieldName: string
): number | undefined {
  if (duration === undefined) {
    return undefined;
  }

  return durationToSeconds(duration, fieldName);
}

export function assertAccessTokenTtlWithinLimit(
  ttlSeconds: number,
  maxTtlSeconds: number,
  fieldName: string
): void {
  if (ttlSeconds > maxTtlSeconds) {
    throw new JwtShieldInsecureConfigError(
      `${fieldName} cannot be greater than maxAccessTokenTtl.`
    );
  }
}

export function assertNoSensitiveClaims(value: unknown, path = 'payload'): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertNoSensitiveClaims(item, `${path}[${index}]`);
    });
    return;
  }

  if (!isRecord(value)) {
    return;
  }

  for (const [key, nestedValue] of Object.entries(value)) {
    if (SENSITIVE_CLAIM_KEYS.has(normalizeClaimKey(key))) {
      throw new JwtShieldInvalidClaimsError(
        `Sensitive claim "${path}.${key}" is not allowed in strict mode. Keep secrets, passwords, and refresh tokens out of JWT payloads.`
      );
    }

    assertNoSensitiveClaims(nestedValue, `${path}.${key}`);
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readDuration(
  duration: JwtShieldDuration | undefined,
  defaultValue: number,
  fieldName: string
): number {
  return duration === undefined
    ? defaultValue
    : durationToSeconds(duration, fieldName);
}

function normalizeAudience(audience: string | string[]): string | string[] {
  if (typeof audience === 'string') {
    return normalizeNonEmptyString(audience, 'audience');
  }

  if (!Array.isArray(audience) || audience.length === 0) {
    throw new JwtShieldInsecureConfigError(
      'audience must be a non-empty string or non-empty string array.'
    );
  }

  return audience.map((entry, index) =>
    normalizeNonEmptyString(entry, `audience[${index}]`)
  );
}

function normalizeNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new JwtShieldInsecureConfigError(`${fieldName} must be a non-empty string.`);
  }

  return value.trim();
}

function normalizeClaimKey(key: string): string {
  return key.replace(/[-_]/g, '').toLowerCase();
}
