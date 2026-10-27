import { db } from "../db/client.js";

export default function runReport(name: string) {
  return db.execute(`CALL report_${name}()`);
}
