import { db } from "../db/client.js";

class LedgerRepo {
  constructor(private readonly conn: typeof db) {}

  byAccount(account: string) {
    return this.conn.query("SELECT amount FROM ledger WHERE account = '" + account + "'");
  }
}

export class Ledger {
  constructor(private repo: LedgerRepo) {}

  find(account: string) {
    return this.repo.byAccount(account);
  }
}

export const ledger = new Ledger(new LedgerRepo(db));
