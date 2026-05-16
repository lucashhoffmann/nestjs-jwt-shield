import { Controller, Get } from '@nestjs/common';
import { CurrentUser, Scopes } from 'nestjs-jwt-shield';
import type { AccessTokenClaims } from '../auth/claims/access-token.claims';

@Controller('admin')
export class AdminController {
  @Scopes('admin:read')
  @Get()
  getAdminArea(@CurrentUser() user: AccessTokenClaims) {
    return {
      message: 'Welcome to the admin area.',
      requestedBy: user.email
    };
  }
}
