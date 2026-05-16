import { SetMetadata } from "@nestjs/common";
import { JWT_SHIELD_IMPERSONATION_POLICY_METADATA } from "../jwt-shield.constants";

export type JwtShieldImpersonationPolicy = "allow" | "deny" | "require";

export const AllowImpersonation = () =>
  SetMetadata(JWT_SHIELD_IMPERSONATION_POLICY_METADATA, "allow");

export const DenyImpersonation = () =>
  SetMetadata(JWT_SHIELD_IMPERSONATION_POLICY_METADATA, "deny");

export const RequireImpersonation = () =>
  SetMetadata(JWT_SHIELD_IMPERSONATION_POLICY_METADATA, "require");
