import { createParamDecorator, ExecutionContext } from '@nestjs/common';

interface RequestWithUser {
  user?: unknown;
}

export const CurrentUser = createParamDecorator(
  <TUser extends Record<string, unknown> = Record<string, unknown>>(
    data: keyof TUser | undefined,
    context: ExecutionContext
  ): TUser | TUser[keyof TUser] | undefined => {
    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user as TUser | undefined;

    if (!data) {
      return user;
    }

    return user?.[data];
  }
);
