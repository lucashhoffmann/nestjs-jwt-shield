import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { JwtShieldService } from "nestjs-jwt-shield";
import { UsersRepository } from "../../../users/application/ports/users.repository";
import type { AccessTokenClaims, JwtClaims } from "../../claims/access-token.claims";

export interface ImpersonateInput {
  actor: AccessTokenClaims;
  subjectUserId: string;
  reason?: string;
}

export interface ImpersonateOutput {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: "10m";
  actingAs: {
    sub: string;
    email: string;
  };
  actor: {
    sub: string;
    email?: string;
  };
}

@Injectable()
export class ImpersonateUseCase {
  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly jwtShield: JwtShieldService<JwtClaims>,
  ) {}

  async execute(input: ImpersonateInput): Promise<ImpersonateOutput> {
    if (!input.actor.scopes?.includes("admin:read")) {
      throw new ForbiddenException("Only admins can impersonate users.");
    }

    if (input.actor.sub === input.subjectUserId) {
      throw new ForbiddenException("You cannot impersonate yourself.");
    }

    const subject = await this.usersRepository.findById(input.subjectUserId);

    if (!subject) {
      throw new NotFoundException("User to impersonate was not found.");
    }

    const accessToken = await this.jwtShield.signImpersonationToken({
      actor: {
        sub: input.actor.sub,
        ...(input.actor.email ? { email: input.actor.email } : {}),
      },
      subject: {
        sub: subject.id,
        email: subject.email,
        scopes: subject.scopes,
      },
      reason: input.reason ?? "support",
    });

    return {
      accessToken,
      tokenType: "Bearer",
      expiresIn: "10m",
      actingAs: {
        sub: subject.id,
        email: subject.email,
      },
      actor: {
        sub: input.actor.sub,
        ...(input.actor.email ? { email: input.actor.email } : {}),
      },
    };
  }
}
