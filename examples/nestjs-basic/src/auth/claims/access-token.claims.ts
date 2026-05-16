import { z } from "zod";

export const accessTokenClaimsSchema = z.object({
  sub: z.uuid(),
  email: z.email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("access"),
});

export const impersonationTokenClaimsSchema = z.object({
  sub: z.uuid(),
  email: z.email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("impersonation"),
  act: z.object({
    sub: z.uuid(),
    email: z.email().optional(),
  }),
  impersonation: z.object({
    startedAt: z.number().int(),
    reason: z.string().optional(),
  }),
});

export const jwtClaimsSchema = z.discriminatedUnion("type", [
  accessTokenClaimsSchema,
  impersonationTokenClaimsSchema,
]);

export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;
export type ImpersonationTokenClaims = z.infer<
  typeof impersonationTokenClaimsSchema
>;
export type JwtClaims = z.infer<typeof jwtClaimsSchema>;
