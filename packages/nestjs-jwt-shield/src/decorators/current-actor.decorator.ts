import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { isJwtShieldImpersonationClaims } from "../impersonation/jwt-shield-impersonation";

interface RequestWithUser {
  user?: unknown;
}

export const CurrentActor = createParamDecorator(
  <TActor extends Record<string, unknown> = Record<string, unknown>>(
    data: keyof TActor | undefined,
    context: ExecutionContext,
  ): TActor | TActor[keyof TActor] | undefined => {
    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    if (!isJwtShieldImpersonationClaims(user)) {
      return undefined;
    }

    const actor = user.act as unknown as TActor;

    if (!data) {
      return actor;
    }

    return actor[data];
  },
);
