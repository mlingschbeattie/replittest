import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scannerRouter from "./scanner";
import cveRouter from "./cve";
import hashRouter from "./hash";
import statsRouter from "./stats";

const router: IRouter = Router();

router.use(healthRouter);
router.use(scannerRouter);
router.use(cveRouter);
router.use(hashRouter);
router.use(statsRouter);

export default router;
