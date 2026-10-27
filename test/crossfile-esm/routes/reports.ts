import { Router, type Request, type Response } from "express";
import orders, { findUser as lookupUser } from "../db/index.js";
import * as reports from "../services/reports.js";
import runReport from "../services/run.js";

export const router = Router();

router.get("/user", async (req: Request, res: Response) => {
  res.json(await lookupUser(String(req.query.name)));
});

router.get("/order/:id", async (req: Request, res: Response) => {
  res.json(await orders.findOrder(req.params.id));
});

router.get("/monthly", async (req: Request, res: Response) => {
  res.json(await reports.byMonth(req.query.month as string));
});

router.post("/run", async (req: Request, res: Response) => {
  res.json(await runReport(req.body.name));
});
