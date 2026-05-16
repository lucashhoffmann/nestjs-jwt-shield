import { Module } from '@nestjs/common';
import { JwtShieldModule } from 'nestjs-jwt-shield';
import { AdminController } from './admin/admin.controller';
import { ImpersonateUseCase } from './auth/application/use-cases/impersonate.use-case';
import { LoginUseCase } from './auth/application/use-cases/login.use-case';
import { jwtClaimsSchema } from './auth/claims/access-token.claims';
import { AuthController } from './auth/auth.controller';
import { PublicController } from './public.controller';
import { UsersRepository } from './users/application/ports/users.repository';
import { ListUsersUseCase } from './users/application/use-cases/list-users.use-case';
import { FakeUsersRepository } from './users/infrastructure/fake-users.repository';
import { UsersController } from './users/users.controller';

@Module({
  imports: [
    JwtShieldModule.register({
      isGlobal: true,
      useGlobalGuard: true,
      issuer: 'nestjs-jwt-shield-example',
      audience: 'nestjs-jwt-shield-example-users',
      algorithm: 'HS256',
      secret:
        process.env.JWT_SECRET ??
        'local-development-secret-key-at-least-32-bytes-long',
      accessTokenTtl: '15m',
      impersonationTokenTtl: '10m',
      claimsSchema: jwtClaimsSchema
    })
  ],
  controllers: [
    AuthController,
    UsersController,
    AdminController,
    PublicController
  ],
  providers: [
    LoginUseCase,
    ImpersonateUseCase,
    ListUsersUseCase,
    {
      provide: UsersRepository,
      useClass: FakeUsersRepository
    }
  ]
})
export class AppModule {}
