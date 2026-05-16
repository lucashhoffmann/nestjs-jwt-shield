import type { User, UserWithPassword } from "../../domain/user.entity";

export abstract class UsersRepository {
  abstract findByEmail(email: string): Promise<UserWithPassword | undefined>;

  abstract findAll(): Promise<User[]>;
}
