import { JwtShieldInsecureConfigError } from '../errors/jwt-shield.errors';
import type { JwtShieldDuration } from '../types/jwt-shield-options';

const DURATION_PATTERN = /^(\d+)(s|m|h)$/;

const DURATION_MULTIPLIERS = {
  s: 1,
  m: 60,
  h: 60 * 60
} as const;

export function nowInSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function durationToSeconds(
  duration: JwtShieldDuration,
  fieldName = 'duration'
): number {
  if (typeof duration === 'number') {
    assertPositiveInteger(duration, fieldName);
    return duration;
  }

  const match = DURATION_PATTERN.exec(duration);

  if (!match) {
    throw new JwtShieldInsecureConfigError(
      `${fieldName} must be a positive integer number of seconds or a string like "15m", "60s", or "1h".`
    );
  }

  const amount = Number(match[1]);
  const unit = match[2] as keyof typeof DURATION_MULTIPLIERS;
  const seconds = amount * DURATION_MULTIPLIERS[unit];

  assertPositiveInteger(seconds, fieldName);
  return seconds;
}

export function assertPositiveInteger(value: number, fieldName: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new JwtShieldInsecureConfigError(
      `${fieldName} must be a positive safe integer.`
    );
  }
}
