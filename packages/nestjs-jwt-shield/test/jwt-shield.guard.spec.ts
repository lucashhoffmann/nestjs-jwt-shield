import "reflect-metadata";
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  DenyImpersonation,
  RequireImpersonation,
} from "../src/decorators/impersonation.decorator";
import { Public } from "../src/decorators/public.decorator";
import { Scopes } from "../src/decorators/scopes.decorator";
import { JwtShieldGuard } from "../src/jwt-shield.guard";
import { JwtShieldService } from "../src/jwt-shield.service";
import { resolveJwtShieldOptions } from "../src/utils/assert-secure-config";

const secret = "test-secret-key-with-at-least-thirty-two-bytes";

const claimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("access"),
});

const impersonationClaimsSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("impersonation"),
  act: z.object({
    sub: z.string().uuid(),
    email: z.string().email().optional(),
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

type JwtClaims = z.infer<typeof mixedClaimsSchema>;

class GuardFixture {
  @Public()
  publicRoute() {
    return undefined;
  }

  protectedRoute() {
    return undefined;
  }

  @Scopes("users:read")
  usersRoute() {
    return undefined;
  }

  @Scopes("admin:read")
  adminRoute() {
    return undefined;
  }

  @DenyImpersonation()
  sensitiveRoute() {
    return undefined;
  }

  @RequireImpersonation()
  impersonationOnlyRoute() {
    return undefined;
  }
}

describe("JwtShieldGuard", () => {
  it("accepts routes marked with @Public()", async () => {
    const { guard } = createGuard();
    const request = createRequest();
    const context = createExecutionContext(
      GuardFixture.prototype.publicRoute,
      request,
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toBeUndefined();
  });

  it("rejects protected routes without a bearer token", async () => {
    const { guard } = createGuard();
    const context = createExecutionContext(
      GuardFixture.prototype.protectedRoute,
      createRequest(),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it("attaches the verified user to request.user", async () => {
    const { guard, service } = createGuard();
    const token = await service.signAccessToken({
      sub: "11111111-1111-4111-8111-111111111111",
      email: "admin@example.com",
      scopes: ["users:read"],
      type: "access",
    });
    const request = createRequest(token);
    const context = createExecutionContext(
      GuardFixture.prototype.protectedRoute,
      request,
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toMatchObject({
      sub: "11111111-1111-4111-8111-111111111111",
      email: "admin@example.com",
    });
  });

  it("accepts a route when the required scope is present", async () => {
    const { guard, service } = createGuard();
    const token = await service.signAccessToken({
      sub: "11111111-1111-4111-8111-111111111111",
      scopes: ["users:read"],
      type: "access",
    });
    const context = createExecutionContext(
      GuardFixture.prototype.usersRoute,
      createRequest(token),
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it("rejects a route when the required scope is missing", async () => {
    const { guard, service } = createGuard();
    const token = await service.signAccessToken({
      sub: "11111111-1111-4111-8111-111111111111",
      scopes: ["users:read"],
      type: "access",
    });
    const context = createExecutionContext(
      GuardFixture.prototype.adminRoute,
      createRequest(token),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it("rejects an impersonation token on routes marked with @DenyImpersonation()", async () => {
    const { guard, service } = createGuard();
    const token = await service.signImpersonationToken({
      actor: {
        sub: "11111111-1111-4111-8111-111111111111",
        email: "admin@example.com",
      },
      subject: {
        sub: "22222222-2222-4222-8222-222222222222",
        email: "user@example.com",
        scopes: ["users:read"],
      },
      reason: "support",
    });
    const context = createExecutionContext(
      GuardFixture.prototype.sensitiveRoute,
      createRequest(token),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it("requires an impersonation token on routes marked with @RequireImpersonation()", async () => {
    const { guard, service } = createGuard();
    const token = await service.signAccessToken({
      sub: "11111111-1111-4111-8111-111111111111",
      scopes: ["users:read"],
      type: "access",
    });
    const context = createExecutionContext(
      GuardFixture.prototype.impersonationOnlyRoute,
      createRequest(token),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it("accepts an impersonation token on routes marked with @RequireImpersonation()", async () => {
    const { guard, service } = createGuard();
    const token = await service.signImpersonationToken({
      actor: {
        sub: "11111111-1111-4111-8111-111111111111",
        email: "admin@example.com",
      },
      subject: {
        sub: "22222222-2222-4222-8222-222222222222",
        email: "user@example.com",
        scopes: ["users:read"],
      },
      reason: "support",
    });
    const request = createRequest(token);
    const context = createExecutionContext(
      GuardFixture.prototype.impersonationOnlyRoute,
      request,
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toMatchObject({
      sub: "22222222-2222-4222-8222-222222222222",
      type: "impersonation",
      act: {
        sub: "11111111-1111-4111-8111-111111111111",
      },
    });
  });
});

function createGuard(): {
  guard: JwtShieldGuard;
  service: JwtShieldService<JwtClaims>;
} {
  const service = new JwtShieldService<JwtClaims>(
    resolveJwtShieldOptions<JwtClaims>({
      issuer: "https://auth.example.test",
      audience: "nestjs-jwt-shield-tests",
      algorithm: "HS256",
      secret,
      claimsSchema: mixedClaimsSchema,
    }),
  );

  return {
    guard: new JwtShieldGuard(new Reflector(), service),
    service,
  };
}

function createRequest(token?: string): {
  headers: Record<string, string>;
  user?: unknown;
} {
  return {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  };
}

function createExecutionContext(
  handler: () => undefined,
  request: { headers: Record<string, string>; user?: unknown },
): ExecutionContext {
  return {
    getClass: () => GuardFixture,
    getHandler: () => handler,
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  } as unknown as ExecutionContext;
}
