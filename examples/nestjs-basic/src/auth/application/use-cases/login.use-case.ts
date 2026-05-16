import { Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtShieldService } from "nestjs-jwt-shield";
import type { JwtClaims } from "../../claims/access-token.claims";
import { UsersRepository } from "../../../users/application/ports/users.repository";

export interface LoginInput {
  email?: string;
  password?: string;
}

export interface LoginOutput {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: "15m";
}

@Injectable()
export class LoginUseCase {
  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly jwtShield: JwtShieldService<JwtClaims>,
  ) {}

  async execute(input: LoginInput): Promise<LoginOutput> {
    const user = input.email
      ? await this.usersRepository.findByEmail(input.email)
      : undefined;

    if (!user || user.password !== input.password) {
      throw new UnauthorizedException("Invalid email or password.");
    }

    const accessToken = await this.jwtShield.signAccessToken({
      sub: user.id,
      email: user.email,
      scopes: user.scopes,
      type: "access",
    });

    return {
      accessToken,
      tokenType: "Bearer",
      expiresIn: "15m",
    };
  }
}
