import type { User, UserWithPassword } from "../../domain/user.entity";

export abstract class UsersRepository {
  abstract findByEmail(email: string): Promise<UserWithPassword | undefined>;

  abstract findById(id: string): Promise<User | undefined>;

  abstract findAll(): Promise<User[]>;
}
