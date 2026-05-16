export class JwtShieldError extends Error {
  readonly code: string;

  readonly cause?: unknown;

  constructor(message: string, code: string, cause?: unknown) {
    super(message);
    this.name = new.target.name;
    this.code = code;

    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

export class JwtShieldMissingTokenError extends JwtShieldError {
  constructor(message = 'Missing Authorization Bearer token.') {
    super(message, 'JWT_SHIELD_MISSING_TOKEN');
  }
}

export class JwtShieldInvalidTokenError extends JwtShieldError {
  constructor(message = 'Invalid access token.', cause?: unknown) {
    super(message, 'JWT_SHIELD_INVALID_TOKEN', cause);
  }
}

export class JwtShieldExpiredTokenError extends JwtShieldError {
  constructor(message = 'Access token has expired.', cause?: unknown) {
    super(message, 'JWT_SHIELD_EXPIRED_TOKEN', cause);
  }
}

export class JwtShieldInvalidClaimsError extends JwtShieldError {
  constructor(message = 'Access token claims are invalid.', cause?: unknown) {
    super(message, 'JWT_SHIELD_INVALID_CLAIMS', cause);
  }
}

export class JwtShieldMissingScopeError extends JwtShieldError {
  readonly missingScopes: string[];

  constructor(missingScopes: string[]) {
    const scopeList = missingScopes.join(', ');
    super(
      `Missing required scope${missingScopes.length === 1 ? '' : 's'}: ${scopeList}.`,
      'JWT_SHIELD_MISSING_SCOPE'
    );
    this.missingScopes = missingScopes;
  }
}

export class JwtShieldInsecureConfigError extends JwtShieldError {
  constructor(message: string) {
    super(message, 'JWT_SHIELD_INSECURE_CONFIG');
  }
}
