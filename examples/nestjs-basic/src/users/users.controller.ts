import { Controller, Get } from "@nestjs/common";
import { CurrentUser, Scopes } from "nestjs-jwt-shield";
import type { JwtClaims } from "../auth/claims/access-token.claims";
import { ListUsersUseCase } from "./application/use-cases/list-users.use-case";

@Controller("users")
export class UsersController {
  constructor(private readonly listUsersUseCase: ListUsersUseCase) {}

  @Scopes("users:read")
  @Get()
  async listUsers(@CurrentUser() user: JwtClaims) {
    const result = await this.listUsersUseCase.execute();

    return {
      requestedBy: user.email,
      users: result.users,
    };
  }
}
