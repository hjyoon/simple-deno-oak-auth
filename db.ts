import { Database } from "https://deno.land/x/aloedb@0.9.0/mod.ts";

export interface User {
  id: string | number[];
  email: string;
  password: string;
  displayName: string;
}

const users = new Database<User>({
  path: "./users.json",
  pretty: true,
  autoload: true,
  autosave: true,
  optimize: true,
  immutable: true,
});

export const db = { users };
