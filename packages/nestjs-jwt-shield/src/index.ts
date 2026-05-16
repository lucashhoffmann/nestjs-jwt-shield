export { JwtShieldModule } from './jwt-shield.module';
export { JwtShieldService } from './jwt-shield.service';
export { JwtShieldGuard } from './jwt-shield.guard';

export { CurrentActor } from './decorators/current-actor.decorator';
export { CurrentUser } from './decorators/current-user.decorator';
export {
  AllowImpersonation,
  DenyImpersonation,
  RequireImpersonation,
  type JwtShieldImpersonationPolicy
} from './decorators/impersonation.decorator';
export { Public } from './decorators/public.decorator';
export { Scopes } from './decorators/scopes.decorator';

export * from './errors/jwt-shield.errors';
export * from './impersonation/jwt-shield-impersonation';
export * from './types/jwt-shield-claims';
export * from './types/jwt-shield-options';
