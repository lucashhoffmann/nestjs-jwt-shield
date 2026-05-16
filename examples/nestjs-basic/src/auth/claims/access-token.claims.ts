import { z } from "zod";

export const accessTokenClaimsSchema = z.object({
  sub: z.uuid(),
  email: z.email().optional(),
  scopes: z.array(z.string()).optional(),
  type: z.literal("access"),
});

export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;
