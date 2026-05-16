import { SetMetadata } from '@nestjs/common';
import { JWT_SHIELD_PUBLIC_METADATA } from '../jwt-shield.constants';

export const Public = () => SetMetadata(JWT_SHIELD_PUBLIC_METADATA, true);
