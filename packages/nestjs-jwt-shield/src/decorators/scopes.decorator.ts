import { SetMetadata } from '@nestjs/common';
import { JWT_SHIELD_SCOPES_METADATA } from '../jwt-shield.constants';

export const Scopes = (...scopes: string[]) =>
  SetMetadata(JWT_SHIELD_SCOPES_METADATA, scopes);
