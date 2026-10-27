import { db } from "./client.js";

export default {
  async findOrder(id: string) {
    return db.query("SELECT id, total FROM orders WHERE id = ?", [id]);
  },
};
