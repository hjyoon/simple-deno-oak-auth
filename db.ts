import { Database } from "https://deno.land/x/aloedb@0.9.0/mod.ts";

const users = new Database({
  path: "./users.json",
  pretty: true,
  autoload: true,
  autosave: true,
  optimize: true,
  immutable: true,
});

export const db = { users };
