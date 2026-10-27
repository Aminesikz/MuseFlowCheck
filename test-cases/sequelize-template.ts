import express, { Request, Response } from 'express';
import { QueryTypes, Sequelize } from 'sequelize';

const sequelize = new Sequelize(process.env.DATABASE_URL as string);
export const ticketsRouter = express.Router();

ticketsRouter.get('/tickets/:state', async (req: Request, res: Response) => {
  const wanted = String(req.params.state).toLowerCase();
  const rows = await sequelize.query(
    `SELECT id, title FROM tickets WHERE state = '${wanted}' ORDER BY created_at DESC`,
    { type: QueryTypes.SELECT }
  );
  res.json(rows);
});
