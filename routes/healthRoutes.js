import express from 'express';
import { getLatestHaState } from '../services/haService.js';
import { getVictronData } from '../services/victronService.js';
import { getGrowattData } from '../services/growattService.js';
import { getCombinedCachedData } from '../services/cacheService.js';

const router = express.Router();

router.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'johnetravels-solar-api',
    version: '2.0.0',
    time: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime())
  });
});

router.get('/full', async (req, res) => {
  const checks = {
    ha: false,
    victron: false,
    growatt: false,
    cachedData: false
  };

  const errors = {};

  try {
    await getLatestHaState();
    checks.ha = true;
  } catch (error) {
    errors.ha = error.message;
  }

  try {
    await getVictronData();
    checks.victron = true;
  } catch (error) {
    errors.victron = error.message;
  }

  try {
    await getGrowattData();
    checks.growatt = true;
  } catch (error) {
    errors.growatt = error.message;
  }

  try {
    const cached = await getCombinedCachedData();
    checks.cachedData = Boolean(cached);
  } catch (error) {
    errors.cachedData = error.message;
  }

  const ok = Object.values(checks).every(Boolean);

  res.status(ok ? 200 : 503).json({
    ok,
    service: 'johnetravels-solar-api',
    version: '2.0.0',
    time: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    checks,
    errors
  });
});

export default router;
