import { Inject, Injectable } from '@nestjs/common';
import {
  SignJWT,
  decodeJwt,
  errors as JoseErrors,
  jwtVerify,
  type JWTPayload
} from 'jose';
import { JWT_SHIELD_OPTIONS } from './jwt-shield.constants';
import {
  JwtShieldError,
  JwtShieldExpiredTokenError,
  JwtShieldInvalidClaimsError,
  JwtShieldInvalidTokenError
} from './errors/jwt-shield.errors';
import type {
  JwtShieldAccessTokenPayload,
  JwtShieldDefaultClaims,
  JwtShieldRegisteredClaims,
  JwtShieldVerifiedClaims
} from './types/jwt-shield-claims';
import type {
  JwtShieldResolvedOptions,
  JwtShieldSignAccessTokenOptions
} from './types/jwt-shield-options';
import {
  assertAccessTokenTtlWithinLimit,
  assertNoSensitiveClaims,
  isRecord,
  readOptionalDuration
} from './utils/assert-secure-config';
import { nowInSeconds } from './utils/time';

const MANAGED_REGISTERED_CLAIMS = new Set(['exp', 'iat', 'iss', 'aud']);

@Injectable()
export class JwtShieldService<TClaims extends object = JwtShieldDefaultClaims> {
  private readonly secretKey: Uint8Array;

  constructor(
    @Inject(JWT_SHIELD_OPTIONS)
    private readonly options: JwtShieldResolvedOptions<TClaims>
  ) {
    this.secretKey = new TextEncoder().encode(options.secret);
  }

  async signAccessToken(
    payload: JwtShieldAccessTokenPayload<TClaims>,
    signOptions: JwtShieldSignAccessTokenOptions = {}
  ): Promise<string> {
    const ttlSeconds =
      readOptionalDuration(signOptions.accessTokenTtl, 'accessTokenTtl') ??
      this.options.accessTokenTtlSeconds;

    assertAccessTokenTtlWithinLimit(
      ttlSeconds,
      this.options.maxAccessTokenTtlSeconds,
      'accessTokenTtl'
    );

    if (this.options.strict) {
      assertNoSensitiveClaims(payload);
    }

    const claims = this.validateApplicationClaims(payload, 'sign');
    const issuedAt = nowInSeconds();

    return new SignJWT(claims as JWTPayload)
      .setProtectedHeader({
        alg: this.options.algorithm,
        typ: 'JWT'
      })
      .setIssuer(this.options.issuer)
      .setAudience(this.options.audience)
      .setSubject(claims.sub)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + ttlSeconds)
      .sign(this.secretKey);
  }

  async verifyAccessToken(token: string): Promise<JwtShieldVerifiedClaims<TClaims>> {
    if (typeof token !== 'string' || token.trim().length === 0) {
      throw new JwtShieldInvalidTokenError('Access token must be a non-empty string.');
    }

    try {
      const result = await jwtVerify(token, this.secretKey, {
        issuer: this.options.issuer,
        audience: this.options.audience,
        algorithms: [this.options.algorithm],
        clockTolerance: this.options.clockToleranceSeconds
      });

      if (result.protectedHeader.alg !== this.options.algorithm) {
        throw new JwtShieldInvalidTokenError(
          `Unexpected JWT alg "${String(result.protectedHeader.alg)}".`
        );
      }

      const registeredClaims = this.assertRegisteredClaims(result.payload);
      const applicationClaims = this.validateApplicationClaims(
        result.payload,
        'verify'
      );

      return {
        ...applicationClaims,
        ...registeredClaims
      };
    } catch (error) {
      if (error instanceof JwtShieldError) {
        throw error;
      }

      if (error instanceof JoseErrors.JWTExpired) {
        throw new JwtShieldExpiredTokenError(undefined, error);
      }

      throw new JwtShieldInvalidTokenError('Access token verification failed.', error);
    }
  }

  /**
   * Decodes JWT claims without validating the signature, expiration, issuer, or audience.
   * Use this only for debugging or non-security decisions.
   */
  decodeUnsafe<TDecoded extends object = JwtShieldVerifiedClaims<TClaims>>(
    token: string
  ): TDecoded {
    try {
      return decodeJwt(token) as TDecoded;
    } catch (error) {
      throw new JwtShieldInvalidTokenError('JWT could not be decoded.', error);
    }
  }

  private validateApplicationClaims(
    payload: unknown,
    action: 'sign' | 'verify'
  ): TClaims & { sub: string } {
    if (!isRecord(payload)) {
      throw new JwtShieldInvalidClaimsError('JWT payload must be an object.');
    }

    const candidateClaims = omitManagedRegisteredClaims(payload);
    const claims = this.options.claimsSchema
      ? this.parseWithSchema(candidateClaims, action)
      : candidateClaims;

    if (!isRecord(claims)) {
      throw new JwtShieldInvalidClaimsError('JWT claims schema must return an object.');
    }

    if (typeof claims.sub !== 'string' || claims.sub.trim().length === 0) {
      throw new JwtShieldInvalidClaimsError(
        'JWT claims must include a non-empty string "sub" claim.'
      );
    }

    return {
      ...(claims as TClaims),
      sub: claims.sub
    };
  }

  private parseWithSchema(payload: Record<string, unknown>, action: 'sign' | 'verify'): TClaims {
    const result = this.options.claimsSchema!.safeParse(payload);

    if (!result.success) {
      const details = result.error.issues
        .map((issue) => {
          const path = issue.path.length > 0 ? issue.path.join('.') : '<root>';
          return `${path}: ${issue.message}`;
        })
        .join('; ');

      throw new JwtShieldInvalidClaimsError(
        `JWT claims failed ${action} validation: ${details}`,
        result.error
      );
    }

    return result.data;
  }

  private assertRegisteredClaims(payload: JWTPayload): JwtShieldRegisteredClaims {
    if (typeof payload.sub !== 'string' || payload.sub.trim().length === 0) {
      throw new JwtShieldInvalidClaimsError('JWT is missing required "sub" claim.');
    }

    if (typeof payload.exp !== 'number') {
      throw new JwtShieldInvalidClaimsError('JWT is missing required "exp" claim.');
    }

    if (typeof payload.iat !== 'number') {
      throw new JwtShieldInvalidClaimsError('JWT is missing required "iat" claim.');
    }

    if (payload.iss !== this.options.issuer) {
      throw new JwtShieldInvalidClaimsError('JWT issuer claim is invalid.');
    }

    if (!hasAudience(payload.aud)) {
      throw new JwtShieldInvalidClaimsError('JWT is missing required "aud" claim.');
    }

    return {
      sub: payload.sub,
      exp: payload.exp,
      iat: payload.iat,
      iss: payload.iss,
      aud: payload.aud
    };
  }
}

function omitManagedRegisteredClaims(
  payload: Record<string, unknown>
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(payload).filter(([key]) => !MANAGED_REGISTERED_CLAIMS.has(key))
  );
}

function hasAudience(audience: unknown): audience is string | string[] {
  return (
    typeof audience === 'string' ||
    (Array.isArray(audience) && audience.every((entry) => typeof entry === 'string'))
  );
}
