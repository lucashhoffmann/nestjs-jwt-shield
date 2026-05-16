# nestjs-jwt-shield

Secure-by-default JWT authentication for NestJS.

`nestjs-jwt-shield` is an opinionated TypeScript library for stateless access-token authentication in NestJS. It does not invent cryptography: it uses [`jose`](https://github.com/panva/jose) for JWT signing and verification, and adds a NestJS-friendly layer with safe defaults, strict claim validation, guards, decorators, clear errors, and scope checks.

## What It Solves

- Signs and verifies stateless JWT access tokens with a fixed configured algorithm.
- Requires `exp`, `iat`, `iss`, `aud`, and `sub`.
- Validates application claims with Zod.
- Provides `JwtShieldGuard`, `@CurrentUser()`, `@Scopes()`, and `@Public()`.
- Provides optional impersonation helpers with `type: 'impersonation'`, the standard JWT `act` actor claim, `@CurrentActor()`, `@DenyImpersonation()`, and `@RequireImpersonation()`.
- Fails fast when configuration is unsafe.
- Keeps the API small and NestJS-native.

## What It Does Not Solve

JWT access tokens are stateless. Once issued, a valid token remains valid until it expires unless your system adds state somewhere else.

This MVP does not implement logout revocation, token blacklists, refresh token rotation, Redis adapters, database-backed sessions, JWKS, key rotation, RS256, EdDSA, Fastify helpers, GraphQL guards, or Swagger helpers.

If you need immediate logout, account-wide revocation, refresh token rotation, or compromised-token invalidation, you need state such as Redis or a database.

## Installation

```bash
pnpm add nestjs-jwt-shield
```

`jose` and `zod` are installed automatically as package dependencies.
`@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs` are peer dependencies and should already exist in a NestJS application.

## Basic Configuration

```ts
import { Module } from '@nestjs/common';
import { JwtShieldModule } from 'nestjs-jwt-shield';
import { z } from 'zod';

const accessTokenClaimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal('access')
});

const impersonationTokenClaimsSchema = z.object({
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
});

const claimsSchema = z.discriminatedUnion('type', [
  accessTokenClaimsSchema,
  impersonationTokenClaimsSchema
]);

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
      impersonationTokenTtl: '10m',
      claimsSchema
    })
  ]
})
export class AppModule {}
```

The HS256 secret must be at least 32 bytes. Use a high-entropy secret from a secret manager.

## Login Example

```ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtShieldService } from 'nestjs-jwt-shield';

@Injectable()
export class LoginUseCase {
  constructor(private readonly jwtShield: JwtShieldService) {}

  async execute(email: string, password: string) {
    const user = await validateUser(email, password);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    const accessToken = await this.jwtShield.signAccessToken({
      sub: user.id,
      email: user.email,
      scopes: user.scopes,
      type: 'access'
    });

    return { accessToken, tokenType: 'Bearer' };
  }
}
```

## Impersonation

Impersonation is optional and generic. The library does not decide who is allowed to impersonate whom; your application still owns that authorization rule. Once your app allows it, `nestjs-jwt-shield` makes the token shape safe and predictable:

- The effective/current user stays in `sub` and the normal custom claims.
- The original actor is stored in the standard JWT `act` claim.
- The token is marked with `type: 'impersonation'`.
- `@CurrentActor()` returns the original actor.
- `@DenyImpersonation()` blocks impersonated access to sensitive routes.
- `@RequireImpersonation()` makes support/debug routes accept only impersonation tokens.

```ts
const token = await jwtShield.signImpersonationToken({
  actor: {
    sub: admin.id,
    email: admin.email
  },
  subject: {
    sub: user.id,
    email: user.email,
    scopes: user.scopes
  },
  reason: 'support'
});
```

```ts
import {
  CurrentActor,
  CurrentUser,
  DenyImpersonation,
  RequireImpersonation,
  Scopes
} from 'nestjs-jwt-shield';

@DenyImpersonation()
@Scopes('admin:read')
@Post('auth/impersonate/:userId')
impersonate(@CurrentUser() admin: AdminClaims) {
  // Authorize and issue an impersonation token in your use case.
}

@RequireImpersonation()
@Get('auth/actor')
actor(@CurrentUser() user: UserClaims, @CurrentActor() actor: ActorClaims) {
  return { actingAs: user.sub, actor: actor.sub };
}
```

If your project uses two-token impersonation, such as a primary token plus `x-impersonation-token`, you can validate the relationship explicitly:

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

## Protected Routes

If you enable `useGlobalGuard`, every route is protected unless marked with `@Public()`.

```ts
import { Controller, Get } from '@nestjs/common';
import { CurrentUser, Public, Scopes } from 'nestjs-jwt-shield';

@Controller()
export class UsersController {
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
  listUsers() {
    return [];
  }
}
```

You can also use the guard route-by-route:

```ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtShieldGuard } from 'nestjs-jwt-shield';

@UseGuards(JwtShieldGuard)
@Controller('account')
export class AccountController {
  @Get()
  getAccount() {
    return { ok: true };
  }
}
```

## Security Model

- `exp` is required so tokens expire.
- `iss` is required so only your configured issuer is accepted.
- `aud` is required so tokens minted for another audience are rejected.
- The algorithm is fixed from configuration. The library never trusts a dynamic JWT header algorithm as the source of truth.
- `alg=none` is not accepted.
- Strict mode is enabled by default with a 15 minute access-token TTL and a maximum of 1 hour.
- Impersonation tokens default to a shorter 10 minute TTL and are still bounded by `maxAccessTokenTtl`.
- The library rejects obvious sensitive claim names such as `password`, `secret`, `refreshToken`, `apiKey`, and `privateKey` in strict mode.
- Do not put secrets, passwords, API keys, refresh tokens, or private user data in JWT payloads.
- Use `@DenyImpersonation()` on high-risk routes such as password changes, payouts, billing changes, API key management, or tenant administration.
- Real impersonation audit logs and immediate impersonation revocation still require a database or Redis.

## Example App

The real NestJS example lives in `examples/nestjs-basic`.

The example uses a small clean architecture shape:

- `auth/claims` keeps JWT claim schema and types.
- `auth/application/use-cases` keeps login application logic.
- `users/domain` keeps user entities.
- `users/application/ports` keeps repository contracts.
- `users/infrastructure` keeps the fake in-memory repository.
- Controllers stay thin and call use cases directly.

```bash
pnpm install
pnpm build
pnpm --filter nestjs-jwt-shield-example-basic start
```

Try the example:

```bash
curl -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"123456"}'

curl http://localhost:3000/public
curl http://localhost:3000/auth/me -H "authorization: Bearer <token>"
curl http://localhost:3000/users -H "authorization: Bearer <token>"
curl http://localhost:3000/admin -H "authorization: Bearer <token>"
curl -X POST http://localhost:3000/auth/impersonate/22222222-2222-4222-8222-222222222222 \
  -H "authorization: Bearer <admin-token>"
curl http://localhost:3000/auth/actor -H "authorization: Bearer <impersonation-token>"
```

You can also open the Bruno/OpenCollection API client collection from:

```txt
examples/nestjs-basic/endpoints
```

Use the `base` environment from Bruno's environment selector. If the selector still says `Environments`, no environment is active. The collection also defines non-secret defaults at collection level so requests can still run locally, but selecting `base` lets `Auth / login admin` and `Auth / login user` persist `admin_token` and `user_token` back into `environments/base.yml`.

Run `Auth / login admin` before admin-token requests such as `Auth / me`, `Users / list users`, and `Admin / get admin`. Run `Auth / impersonate user` to create `impersonation_token`, then try `Auth / actor as impersonated user` and `Admin / get admin as impersonated user`. Run `Auth / login user` before the `as basic user` requests; those intentionally use `user_token`, not `admin_token`, so `Admin / get admin as basic user` should return `403`.

Fake users:

- `admin@example.com` / `123456` with `users:read` and `admin:read`
- `user@example.com` / `123456` with `users:read`

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm lint
pnpm typecheck
```
