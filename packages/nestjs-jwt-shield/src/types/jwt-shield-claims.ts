export interface JwtShieldDefaultClaims {
  sub: string;
  email?: string;
  roles?: string[];
  scopes?: string[];
  type?: 'access';
}

export interface JwtShieldRegisteredClaims {
  sub: string;
  exp: number;
  iat: number;
  iss: string;
  aud: string | string[];
}

export type JwtShieldAccessTokenPayload<
  TClaims extends object = JwtShieldDefaultClaims
> = TClaims & {
  sub: string;
};

export type JwtShieldVerifiedClaims<
  TClaims extends object = JwtShieldDefaultClaims
> = TClaims & JwtShieldRegisteredClaims;
