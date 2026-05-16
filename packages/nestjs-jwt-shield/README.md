# nestjs-jwt-shield

Secure-by-default JWT authentication for NestJS.

This package provides an opinionated NestJS layer around `jose` with strict claim validation, safe defaults, route guards, current-user decorators, public-route decorators, and scope checks.

## Install

```bash
pnpm add nestjs-jwt-shield jose zod
```

`@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs` are peer dependencies.

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
- Keep secrets, passwords, API keys, refresh tokens, and private user data out of JWT payloads.
- This MVP supports `HS256`; RS256, EdDSA, JWKS, and key rotation are planned future work.
