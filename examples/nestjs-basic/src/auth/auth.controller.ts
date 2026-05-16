import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import {
  CurrentActor,
  CurrentUser,
  DenyImpersonation,
  Public,
  RequireImpersonation,
  Scopes,
} from "nestjs-jwt-shield";
import { ImpersonateUseCase } from "./application/use-cases/impersonate.use-case";
import { LoginUseCase } from "./application/use-cases/login.use-case";
import type {
  AccessTokenClaims,
  ImpersonationTokenClaims,
  JwtClaims,
} from "./claims/access-token.claims";

interface LoginBody {
  email?: string;
  password?: string;
}

@Controller("auth")
export class AuthController {
  constructor(
    private readonly loginUseCase: LoginUseCase,
    private readonly impersonateUseCase: ImpersonateUseCase,
  ) {}

  @Public()
  @Post("login")
  login(@Body() body: LoginBody) {
    return this.loginUseCase.execute(body);
  }

  @Get("me")
  me(@CurrentUser() user: JwtClaims) {
    return {
      user,
    };
  }

  @DenyImpersonation()
  @Scopes("admin:read")
  @Post("impersonate/:userId")
  impersonate(
    @CurrentUser() actor: AccessTokenClaims,
    @Param("userId") userId: string,
  ) {
    return this.impersonateUseCase.execute({
      actor,
      subjectUserId: userId,
    });
  }

  @RequireImpersonation()
  @Get("actor")
  actor(
    @CurrentUser() user: ImpersonationTokenClaims,
    @CurrentActor() actor: ImpersonationTokenClaims["act"],
  ) {
    return {
      actingAs: {
        sub: user.sub,
        email: user.email,
      },
      actor,
      reason: user.impersonation.reason,
    };
  }
}
