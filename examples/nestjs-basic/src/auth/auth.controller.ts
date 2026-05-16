import { Body, Controller, Get, Post } from "@nestjs/common";
import { CurrentUser, Public } from "nestjs-jwt-shield";
import { LoginUseCase } from "./application/use-cases/login.use-case";
import type { AccessTokenClaims } from "./claims/access-token.claims";

interface LoginBody {
  email?: string;
  password?: string;
}

@Controller("auth")
export class AuthController {
  constructor(private readonly loginUseCase: LoginUseCase) {}

  @Public()
  @Post("login")
  login(@Body() body: LoginBody) {
    return this.loginUseCase.execute(body);
  }

  @Get("me")
  me(@CurrentUser() user: AccessTokenClaims) {
    return {
      user,
    };
  }
}
