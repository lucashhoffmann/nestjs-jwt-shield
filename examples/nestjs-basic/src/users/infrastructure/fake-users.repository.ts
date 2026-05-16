import { Injectable } from "@nestjs/common";
import type { User, UserWithPassword } from "../domain/user.entity";
import { UsersRepository } from "../application/ports/users.repository";

@Injectable()
export class FakeUsersRepository implements UsersRepository {
  private readonly users: UserWithPassword[] = [
    {
      id: "11111111-1111-4111-8111-111111111111",
      email: "admin@example.com",
      password: "123456",
      scopes: ["users:read", "admin:read"],
    },
    {
      id: "22222222-2222-4222-8222-222222222222",
      email: "user@example.com",
      password: "123456",
      scopes: ["users:read"],
    },
  ];

  async findByEmail(email: string): Promise<UserWithPassword | undefined> {
    return this.users.find((user) => user.email === email);
  }

  async findById(id: string): Promise<User | undefined> {
    const user = this.users.find((entry) => entry.id === id);

    if (!user) {
      return undefined;
    }

    return {
      id: user.id,
      email: user.email,
      scopes: user.scopes,
    };
  }

  async findAll(): Promise<User[]> {
    return this.users.map((user) => ({
      id: user.id,
      email: user.email,
      scopes: user.scopes,
    }));
  }
}
