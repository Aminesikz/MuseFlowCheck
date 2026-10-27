import { db } from "./client.js";

export async function findUser(name: string) {
  return db.query(`SELECT id FROM users WHERE name = '${name}'`);
}
