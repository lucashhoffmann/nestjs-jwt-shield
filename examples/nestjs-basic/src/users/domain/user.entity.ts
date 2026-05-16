export interface User {
  id: string;
  email: string;
  scopes: string[];
}

export interface UserWithPassword extends User {
  password: string;
}
