import { JwtShieldInvalidImpersonationError } from '../errors/jwt-shield.errors';
import type { JwtShieldDuration } from '../types/jwt-shield-options';
import { nowInSeconds } from '../utils/time';

export interface JwtShieldImpersonationParticipant {
  sub: string;
}

export interface JwtShieldImpersonationMetadata {
  startedAt: number;
  reason?: string;
}

export type JwtShieldImpersonationClaims<
  TSubject extends JwtShieldImpersonationParticipant,
  TActor extends JwtShieldImpersonationParticipant,
  TMetadata extends object = Record<string, never>
> = TSubject & {
  type: 'impersonation';
  act: TActor;
  impersonation: JwtShieldImpersonationMetadata & TMetadata;
};

export type JwtShieldImpersonationVerifiedClaims<TClaims extends object> =
  TClaims & {
    type: 'impersonation';
    act: JwtShieldImpersonationParticipant;
    impersonation: JwtShieldImpersonationMetadata;
  };

export interface JwtShieldSignImpersonationTokenInput<
  TSubject extends JwtShieldImpersonationParticipant,
  TActor extends JwtShieldImpersonationParticipant,
  TMetadata extends object = Record<string, never>
> {
  /**
   * Effective identity. These claims become the normal current user claims.
   */
  subject: TSubject;

  /**
   * Original actor/admin/support user. Stored in the JWT `act` claim.
   */
  actor: TActor;

  /**
   * Human-readable reason useful for audit logs and support tooling.
   */
  reason?: string;

  /**
   * Extra non-sensitive metadata under the `impersonation` claim.
   */
  metadata?: TMetadata;
}

export interface JwtShieldSignImpersonationTokenOptions {
  impersonationTokenTtl?: JwtShieldDuration;
}

export type JwtShieldClaimSelector<TClaims extends object> =
  | string
  | ((claims: TClaims) => unknown);

export interface JwtShieldAssertImpersonationLinkOptions<
  TActor extends object,
  TImpersonation extends object
> {
  actor: TActor;
  impersonation: TImpersonation;
  actorId?: JwtShieldClaimSelector<TActor>;
  impersonationActorId?: JwtShieldClaimSelector<TImpersonation>;
  actorTenantId?: JwtShieldClaimSelector<TActor>;
  impersonationActorTenantId?: JwtShieldClaimSelector<TImpersonation>;
}

export interface JwtShieldVerifyImpersonationSessionInput<
  TActor extends object,
  TImpersonation extends object
> extends Omit<
    JwtShieldAssertImpersonationLinkOptions<TActor, TImpersonation>,
    'actor' | 'impersonation'
  > {
  primaryToken: string;
  impersonationToken: string;
}

export interface JwtShieldImpersonationSession<
  TActor extends object,
  TImpersonation extends object
> {
  primary: TActor;
  actor: TActor;
  impersonation: TImpersonation;
  current: TImpersonation;
}

const RESERVED_SUBJECT_CLAIMS = new Set(['act', 'impersonation', 'type']);

export function createJwtShieldImpersonationClaims<
  TSubject extends JwtShieldImpersonationParticipant,
  TActor extends JwtShieldImpersonationParticipant,
  TMetadata extends object = Record<string, never>
>(
  input: JwtShieldSignImpersonationTokenInput<TSubject, TActor, TMetadata>
): JwtShieldImpersonationClaims<TSubject, TActor, TMetadata> {
  assertParticipant('subject', input.subject);
  assertParticipant('actor', input.actor);
  assertNoReservedSubjectClaims(input.subject);

  const impersonationMetadata = {
    ...(input.metadata ?? ({} as TMetadata)),
    startedAt: nowInSeconds(),
    ...(input.reason === undefined ? {} : { reason: input.reason })
  } as JwtShieldImpersonationMetadata & TMetadata;

  return {
    ...input.subject,
    type: 'impersonation',
    act: input.actor,
    impersonation: impersonationMetadata
  };
}

export function isJwtShieldImpersonationClaims(
  claims: unknown
): claims is JwtShieldImpersonationVerifiedClaims<Record<string, unknown>> {
  return (
    isRecord(claims) &&
    claims.type === 'impersonation' &&
    isRecord(claims.act) &&
    typeof claims.act.sub === 'string' &&
    claims.act.sub.trim().length > 0 &&
    isRecord(claims.impersonation) &&
    typeof claims.impersonation.startedAt === 'number'
  );
}

export function assertJwtShieldImpersonationClaims<TClaims extends object>(
  claims: TClaims
): asserts claims is JwtShieldImpersonationVerifiedClaims<TClaims> {
  if (!isJwtShieldImpersonationClaims(claims)) {
    throw new JwtShieldInvalidImpersonationError(
      'JWT claims are not a valid impersonation token. Expected type "impersonation", an actor claim at "act.sub", and "impersonation.startedAt".'
    );
  }
}

export function assertImpersonationLink<
  TActor extends object,
  TImpersonation extends object
>(
  options: JwtShieldAssertImpersonationLinkOptions<TActor, TImpersonation>
): void {
  assertJwtShieldImpersonationClaims(options.impersonation);

  const actorId = readRequiredSelectedClaim(
    options.actor,
    options.actorId ?? 'sub',
    'actorId'
  );
  const impersonationActorId = readRequiredSelectedClaim(
    options.impersonation,
    options.impersonationActorId ?? 'act.sub',
    'impersonationActorId'
  );

  assertEqualClaim(actorId, impersonationActorId, 'actor id');

  if (options.actorTenantId || options.impersonationActorTenantId) {
    const actorTenantId = readRequiredSelectedClaim(
      options.actor,
      options.actorTenantId ?? 'tenantId',
      'actorTenantId'
    );
    const impersonationActorTenantId = readRequiredSelectedClaim(
      options.impersonation,
      options.impersonationActorTenantId ?? 'act.tenantId',
      'impersonationActorTenantId'
    );

    assertEqualClaim(actorTenantId, impersonationActorTenantId, 'actor tenant id');
  }
}

function assertParticipant(
  name: 'actor' | 'subject',
  value: JwtShieldImpersonationParticipant
): void {
  if (!isRecord(value)) {
    throw new JwtShieldInvalidImpersonationError(
      `Impersonation ${name} must be an object.`
    );
  }

  if (typeof value.sub !== 'string' || value.sub.trim().length === 0) {
    throw new JwtShieldInvalidImpersonationError(
      `Impersonation ${name} must include a non-empty string "sub" claim.`
    );
  }
}

function assertNoReservedSubjectClaims(
  subject: JwtShieldImpersonationParticipant
): void {
  for (const key of Object.keys(subject)) {
    if (RESERVED_SUBJECT_CLAIMS.has(key)) {
      throw new JwtShieldInvalidImpersonationError(
        `Impersonation subject cannot define reserved claim "${key}". The library manages "type", "act", and "impersonation".`
      );
    }
  }
}

function readRequiredSelectedClaim<TClaims extends object>(
  claims: TClaims,
  selector: JwtShieldClaimSelector<TClaims>,
  selectorName: string
): unknown {
  const value = readSelectedClaim(claims, selector);

  if (value === undefined || value === null || value === '') {
    throw new JwtShieldInvalidImpersonationError(
      `Impersonation link validation could not read ${selectorName}.`
    );
  }

  return value;
}

function readSelectedClaim<TClaims extends object>(
  claims: TClaims,
  selector: JwtShieldClaimSelector<TClaims>
): unknown {
  if (typeof selector === 'function') {
    return selector(claims);
  }

  return selector.split('.').reduce<unknown>((current, pathPart) => {
    if (!isRecord(current)) {
      return undefined;
    }

    return current[pathPart];
  }, claims);
}

function assertEqualClaim(left: unknown, right: unknown, label: string): void {
  if (!Object.is(left, right)) {
    throw new JwtShieldInvalidImpersonationError(
      `Impersonation ${label} mismatch. Expected "${String(left)}", got "${String(right)}".`
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
