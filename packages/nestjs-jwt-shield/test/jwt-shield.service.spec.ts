import "reflect-metadata";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  JwtShieldExpiredTokenError,
  JwtShieldInvalidImpersonationError,
  JwtShieldInsecureConfigError,
  JwtShieldInvalidClaimsError,
  JwtShieldInvalidTokenError,
} from "../src/errors/jwt-shield.errors";
import { JwtShieldService } from "../src/jwt-shield.service";
import type { JwtShieldModuleOptions } from "../src/types/jwt-shield-options";
import { resolveJwtShieldOptions } from "../src/utils/assert-secure-config";

const secret = "test-secret-key-with-at-least-thirty-two-bytes";
const issuer = "https://auth.example.test";
const audience = "nestjs-jwt-shield-tests";

const claimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  roles: z.array(z.string()).optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("access"),
});

type AccessClaims = z.infer<typeof claimsSchema>;

const impersonationClaimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("impersonation"),
  act: z.object({
    sub: z.string().uuid(),
    email: z.string().email().optional(),
    tenantId: z.string().uuid().optional(),
  }),
  impersonation: z.object({
    startedAt: z.number().int(),
    reason: z.string().optional(),
  }),
});

const mixedClaimsSchema = z.discriminatedUnion("type", [
  claimsSchema,
  impersonationClaimsSchema,
]);

type MixedClaims = z.infer<typeof mixedClaimsSchema>;

const validPayload = {
  sub: "11111111-1111-4111-8111-111111111111",
  email: "admin@example.com",
  scopes: ["users:read", "admin:read"],
  type: "access",
} satisfies AccessClaims;

describe("JwtShieldService", () => {
  it("signs and verifies a valid access token", async () => {
    const service = createService();

    const token = await service.signAccessToken(validPayload);
    const claims = await service.verifyAccessToken(token);

    expect(token.split(".")).toHaveLength(3);
    expect(claims.sub).toBe(validPayload.sub);
    expect(claims.email).toBe(validPayload.email);
    expect(claims.scopes).toEqual(validPayload.scopes);
    expect(claims.iss).toBe(issuer);
    expect(claims.aud).toBe(audience);
    expect(typeof claims.exp).toBe("number");
    expect(typeof claims.iat).toBe("number");
  });

  it("decodes without verifying when decodeUnsafe is used", async () => {
    const service = createService();
    const token = await service.signAccessToken(validPayload);

    const decoded = service.decodeUnsafe<AccessClaims>(token);

    expect(decoded.sub).toBe(validPayload.sub);
  });

  it("rejects expired access tokens", async () => {
    const service = createService();
    const expiredToken = await signRawToken({
      ...validPayload,
      iat: now() - 120,
      exp: now() - 60,
    });

    await expect(
      service.verifyAccessToken(expiredToken),
    ).rejects.toBeInstanceOf(JwtShieldExpiredTokenError);
  });

  it("rejects tokens with an invalid issuer", async () => {
    const service = createService({
      issuer: "https://another-issuer.example.test",
    });
    const token = await signRawToken(validPayload);

    await expect(service.verifyAccessToken(token)).rejects.toBeInstanceOf(
      JwtShieldInvalidTokenError,
    );
  });

  it("rejects tokens with an invalid audience", async () => {
    const service = createService({ audience: "another-audience" });
    const token = await signRawToken(validPayload);

    await expect(service.verifyAccessToken(token)).rejects.toBeInstanceOf(
      JwtShieldInvalidTokenError,
    );
  });

  it("rejects claims that do not match the Zod schema", async () => {
    const service = createService();
    const token = await signRawToken({
      sub: validPayload.sub,
      email: "not-an-email",
      type: "access",
    });

    await expect(service.verifyAccessToken(token)).rejects.toBeInstanceOf(
      JwtShieldInvalidClaimsError,
    );
  });

  it("rejects sensitive payload claims in strict mode", async () => {
    const service = createService();

    await expect(
      service.signAccessToken({
        ...validPayload,
        password: "please-do-not-do-this",
      } as AccessClaims & { password: string }),
    ).rejects.toBeInstanceOf(JwtShieldInvalidClaimsError);
  });

  it("signs and verifies an impersonation token with actor claims", async () => {
    const service = createMixedService();

    const token = await service.signImpersonationToken(
      {
        actor: {
          sub: "11111111-1111-4111-8111-111111111111",
          email: "admin@example.com",
          tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        },
        subject: {
          sub: "22222222-2222-4222-8222-222222222222",
          email: "user@example.com",
          scopes: ["users:read"],
        },
        reason: "support",
      },
      { impersonationTokenTtl: "5m" },
    );

    const claims = await service.verifyImpersonationToken(token);

    expect(claims.type).toBe("impersonation");
    expect(claims.sub).toBe("22222222-2222-4222-8222-222222222222");
    expect(claims.act.sub).toBe("11111111-1111-4111-8111-111111111111");
    expect(claims.impersonation.reason).toBe("support");
    expect(typeof claims.impersonation.startedAt).toBe("number");
  });

  it("rejects a normal access token when impersonation is required", async () => {
    const service = createMixedService();
    const token = await service.signAccessToken(validPayload);

    await expect(
      service.verifyImpersonationToken(token),
    ).rejects.toBeInstanceOf(JwtShieldInvalidImpersonationError);
  });

  it("validates the link between a primary actor and impersonation token", async () => {
    const service = createMixedService();
    const primaryToken = await service.signAccessToken(validPayload);
    const impersonationToken = await service.signImpersonationToken({
      actor: {
        sub: validPayload.sub,
        email: validPayload.email,
        tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      },
      subject: {
        sub: "22222222-2222-4222-8222-222222222222",
        email: "user@example.com",
        scopes: ["users:read"],
      },
      reason: "support",
    });

    const session = await service.verifyImpersonationSession({
      primaryToken,
      impersonationToken,
      actorTenantId: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      impersonationActorTenantId: "act.tenantId",
    });

    expect(session.actor.sub).toBe(validPayload.sub);
    expect(session.current.sub).toBe("22222222-2222-4222-8222-222222222222");
  });

  it("rejects an impersonation token linked to another actor", async () => {
    const service = createMixedService();
    const primaryToken = await service.signAccessToken(validPayload);
    const impersonationToken = await service.signImpersonationToken({
      actor: {
        sub: "33333333-3333-4333-8333-333333333333",
        email: "another-admin@example.com",
      },
      subject: {
        sub: "22222222-2222-4222-8222-222222222222",
        email: "user@example.com",
      },
    });

    await expect(
      service.verifyImpersonationSession({
        primaryToken,
        impersonationToken,
      }),
    ).rejects.toBeInstanceOf(JwtShieldInvalidImpersonationError);
  });

  it("fails fast for insecure configuration", () => {
    expect(() =>
      createService({
        secret: "too-short",
      }),
    ).toThrow(JwtShieldInsecureConfigError);
  });
});

function createService(
  overrides: Partial<JwtShieldModuleOptions<AccessClaims>> = {},
): JwtShieldService<AccessClaims> {
  const options = resolveJwtShieldOptions<AccessClaims>({
    issuer,
    audience,
    algorithm: "HS256",
    secret,
    accessTokenTtl: "15m",
    claimsSchema,
    ...overrides,
  });

  return new JwtShieldService<AccessClaims>(options);
}

function createMixedService(
  overrides: Partial<JwtShieldModuleOptions<MixedClaims>> = {},
): JwtShieldService<MixedClaims> {
  const options = resolveJwtShieldOptions<MixedClaims>({
    issuer,
    audience,
    algorithm: "HS256",
    secret,
    accessTokenTtl: "15m",
    impersonationTokenTtl: "10m",
    claimsSchema: mixedClaimsSchema,
    ...overrides,
  });

  return new JwtShieldService<MixedClaims>(options);
}

async function signRawToken(payload: Record<string, unknown>): Promise<string> {
  const issuedAt = typeof payload.iat === "number" ? payload.iat : now();
  const expiresAt =
    typeof payload.exp === "number" ? payload.exp : issuedAt + 60;

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: "HS256",
      typ: "JWT",
    })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(String(payload.sub))
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(new TextEncoder().encode(secret));
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}
