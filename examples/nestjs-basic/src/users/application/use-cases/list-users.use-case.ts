import { Injectable } from "@nestjs/common";
import type { User } from "../../domain/user.entity";
import { UsersRepository } from "../ports/users.repository";

export interface ListUsersOutput {
  users: User[];
}

@Injectable()
export class ListUsersUseCase {
  constructor(private readonly usersRepository: UsersRepository) {}

  async execute(): Promise<ListUsersOutput> {
    return {
      users: await this.usersRepository.findAll(),
    };
  }
}
