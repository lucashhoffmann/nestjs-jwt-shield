import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  JWT_SHIELD_PUBLIC_METADATA,
  JWT_SHIELD_IMPERSONATION_POLICY_METADATA,
  JWT_SHIELD_SCOPES_METADATA
} from './jwt-shield.constants';
import {
  JwtShieldError,
  JwtShieldInvalidImpersonationError,
  JwtShieldMissingScopeError,
  JwtShieldMissingTokenError
} from './errors/jwt-shield.errors';
import type { JwtShieldImpersonationPolicy } from './decorators/impersonation.decorator';
import { isJwtShieldImpersonationClaims } from './impersonation/jwt-shield-impersonation';
import { JwtShieldService } from './jwt-shield.service';

interface JwtShieldHttpRequest {
  headers?: {
    authorization?: string | string[];
  };
  user?: unknown;
}

@Injectable()
export class JwtShieldGuard implements CanActivate {
  constructor(
    @Inject(Reflector)
    private readonly reflector: Reflector,
    @Inject(JwtShieldService)
    private readonly jwtShield: JwtShieldService<any>
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.isPublicRoute(context)) {
      return true;
    }

    try {
      const request = context.switchToHttp().getRequest<JwtShieldHttpRequest>();
      const token = extractBearerToken(request.headers?.authorization);
      const user = await this.jwtShield.verifyAccessToken(token);

      this.assertImpersonationPolicy(context, user);
      this.assertRequiredScopes(context, user);
      request.user = user;

      return true;
    } catch (error) {
      if (error instanceof JwtShieldMissingScopeError) {
        throw new ForbiddenException(error.message);
      }

      if (error instanceof JwtShieldInvalidImpersonationError) {
        throw new ForbiddenException(error.message);
      }

      if (error instanceof JwtShieldError) {
        throw new UnauthorizedException(error.message);
      }

      throw error;
    }
  }

  private isPublicRoute(context: ExecutionContext): boolean {
    return (
      this.reflector.getAllAndOverride<boolean>(JWT_SHIELD_PUBLIC_METADATA, [
        context.getHandler(),
        context.getClass()
      ]) ?? false
    );
  }

  private assertRequiredScopes(
    context: ExecutionContext,
    user: { scopes?: unknown }
  ): void {
    const requiredScopes =
      this.reflector.getAllAndOverride<string[]>(JWT_SHIELD_SCOPES_METADATA, [
        context.getHandler(),
        context.getClass()
      ]) ?? [];

    if (requiredScopes.length === 0) {
      return;
    }

    const userScopes = Array.isArray(user.scopes)
      ? user.scopes.filter((scope): scope is string => typeof scope === 'string')
      : [];
    const missingScopes = requiredScopes.filter(
      (scope) => !userScopes.includes(scope)
    );

    if (missingScopes.length > 0) {
      throw new JwtShieldMissingScopeError(missingScopes);
    }
  }

  private assertImpersonationPolicy(
    context: ExecutionContext,
    user: Record<string, unknown>
  ): void {
    const policy =
      this.reflector.getAllAndOverride<JwtShieldImpersonationPolicy>(
        JWT_SHIELD_IMPERSONATION_POLICY_METADATA,
        [context.getHandler(), context.getClass()]
      ) ?? 'allow';

    if (policy === 'allow') {
      return;
    }

    const isImpersonation = isJwtShieldImpersonationClaims(user);

    if (policy === 'deny' && isImpersonation) {
      throw new JwtShieldInvalidImpersonationError(
        'Impersonation tokens are not allowed for this route.'
      );
    }

    if (policy === 'require' && !isImpersonation) {
      throw new JwtShieldInvalidImpersonationError(
        'This route requires an impersonation token.'
      );
    }
  }
}

function extractBearerToken(authorization: string | string[] | undefined): string {
  if (typeof authorization !== 'string') {
    throw new JwtShieldMissingTokenError();
  }

  const [scheme, token, extra] = authorization.trim().split(/\s+/);

  if (scheme !== 'Bearer' || !token || extra) {
    throw new JwtShieldMissingTokenError(
      'Authorization header must use the format: Bearer <token>.'
    );
  }

  return token;
}
