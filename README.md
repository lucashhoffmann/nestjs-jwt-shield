# nestjs-jwt-shield

Secure-by-default JWT authentication for NestJS.

`nestjs-jwt-shield` is an opinionated TypeScript library for stateless access-token authentication in NestJS. It does not invent cryptography: it uses [`jose`](https://github.com/panva/jose) for JWT signing and verification, and adds a NestJS-friendly layer with safe defaults, strict claim validation, guards, decorators, clear errors, and scope checks.

## What It Solves

- Signs and verifies stateless JWT access tokens with a fixed configured algorithm.
- Requires `exp`, `iat`, `iss`, `aud`, and `sub`.
- Validates application claims with Zod.
- Provides `JwtShieldGuard`, `@CurrentUser()`, `@Scopes()`, and `@Public()`.
- Fails fast when configuration is unsafe.
- Keeps the API small and NestJS-native.

## What It Does Not Solve

JWT access tokens are stateless. Once issued, a valid token remains valid until it expires unless your system adds state somewhere else.

This MVP does not implement logout revocation, token blacklists, refresh token rotation, Redis adapters, database-backed sessions, JWKS, key rotation, RS256, EdDSA, Fastify helpers, GraphQL guards, or Swagger helpers.

If you need immediate logout, account-wide revocation, refresh token rotation, or compromised-token invalidation, you need state such as Redis or a database.

## Installation

```bash
pnpm add nestjs-jwt-shield jose zod
pnpm add @nestjs/common @nestjs/core reflect-metadata rxjs
```

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
      claimsSchema: accessTokenClaimsSchema
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
- The library rejects obvious sensitive claim names such as `password`, `secret`, `refreshToken`, `apiKey`, and `privateKey` in strict mode.
- Do not put secrets, passwords, API keys, refresh tokens, or private user data in JWT payloads.

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
```

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
