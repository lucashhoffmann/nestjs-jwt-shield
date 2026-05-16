# nestjs-jwt-shield

Secure-by-default JWT authentication for NestJS.

This package provides an opinionated NestJS layer around `jose` with strict claim validation, safe defaults, route guards, current-user decorators, public-route decorators, and scope checks.

## Install

```bash
pnpm add nestjs-jwt-shield
```

`jose` and `zod` are installed automatically as package dependencies.
`@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs` are peer dependencies and should already exist in a NestJS application.

## Quick Start

```ts
import { Module } from '@nestjs/common';
import { JwtShieldModule } from 'nestjs-jwt-shield';
import { z } from 'zod';

const claimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal('access')
});

@Module({
  imports: [
    JwtShieldModule.register({
      isGlobal: true,
      useGlobalGuard: true,
      issuer: 'my-api',
      audience: 'my-api-users',
      algorithm: 'HS256',
      secret: process.env.JWT_SECRET!,
      accessTokenTtl: '15m',
      claimsSchema
    })
  ]
})
export class AppModule {}
```

## Impersonation

Impersonation support is optional and generic. Your app decides whether an actor can impersonate a subject; the library handles safe JWT shape, validation, and route-level DX.

```ts
const claimsSchema = z.discriminatedUnion('type', [
  z.object({
    sub: z.string().uuid(),
    email: z.string().email().optional(),
    scopes: z.array(z.string()).optional(),
    type: z.literal('access')
  }),
  z.object({
    sub: z.string().uuid(),
    email: z.string().email().optional(),
    scopes: z.array(z.string()).optional(),
    type: z.literal('impersonation'),
    act: z.object({
      sub: z.string().uuid(),
      email: z.string().email().optional()
    }),
    impersonation: z.object({
      startedAt: z.number().int(),
      reason: z.string().optional()
    })
  })
]);

const token = await jwtShield.signImpersonationToken({
  actor: { sub: admin.id, email: admin.email },
  subject: { sub: user.id, email: user.email, scopes: user.scopes },
  reason: 'support'
});
```

```ts
import {
  CurrentActor,
  CurrentUser,
  DenyImpersonation,
  RequireImpersonation
} from 'nestjs-jwt-shield';

@DenyImpersonation()
changePassword() {
  return { ok: true };
}

@RequireImpersonation()
actor(@CurrentUser() user: unknown, @CurrentActor() actor: unknown) {
  return { user, actor };
}
```

For primary-token plus impersonation-token flows:

```ts
const session = await jwtShield.verifyImpersonationSession({
  primaryToken,
  impersonationToken,
  actorId: 'sub',
  impersonationActorId: 'act.sub'
});

request.primaryAuth = session.primary;
request.impersonationAuth = session.impersonation;
request.auth = session.current;
```

## Sign Tokens

```ts
const accessToken = await jwtShield.signAccessToken({
  sub: user.id,
  email: user.email,
  scopes: ['users:read'],
  type: 'access'
});
```

## Protect Routes

```ts
import { Controller, Get } from '@nestjs/common';
import { CurrentUser, Public, Scopes } from 'nestjs-jwt-shield';

@Controller()
export class AppController {
  @Public()
  @Get('public')
  publicRoute() {
    return { ok: true };
  }

  @Get('auth/me')
  me(@CurrentUser() user: unknown) {
    return { user };
  }

  @Scopes('users:read')
  @Get('users')
  users() {
    return [];
  }
}
```

## Important Security Notes

- JWT access tokens are stateless and cannot be revoked immediately without external state.
- Use short-lived access tokens.
- Impersonation tokens default to 10 minutes and should usually be shorter than regular access tokens.
- Use `@DenyImpersonation()` on high-risk operations such as password changes, billing, payouts, API key management, or tenant administration.
- Keep secrets, passwords, API keys, refresh tokens, and private user data out of JWT payloads.
- Real impersonation audit logs and immediate revocation still require a database or Redis.
- This MVP supports `HS256`; RS256, EdDSA, JWKS, and key rotation are planned future work.
