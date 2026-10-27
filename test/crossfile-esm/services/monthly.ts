import { db } from "../db/client.js";

export const byMonth = (month: string) => {
  const sql = "SELECT total FROM reports WHERE month = '" + month + "'";
  return db.query(sql);
};
