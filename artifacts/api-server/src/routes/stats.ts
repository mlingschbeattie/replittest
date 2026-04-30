import { Router, type IRouter } from "express";
import { GetStatsResponse } from "@workspace/api-zod";
import { getStats } from "../lib/activity";

const router: IRouter = Router();

router.get("/stats", (_req, res) => {
  res.json(GetStatsResponse.parse(getStats()));
});

export default router;
