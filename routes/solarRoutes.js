import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { getLastSolarHistoryLines } from '../services/solarHistoryService.js';
import { getVictronData } from '../services/victronService.js';
import { getGrowattData } from '../services/growattService.js';
import { getCombinedCachedData } from '../services/cacheService.js';
import { getLatestHaState, saveHaState, saveHaSensor } from '../services/haService.js';

const router = express.Router();

router.get('/lastEntry', authenticateToken, async (req, res) => {
  try {
    const lastEntry = await getLastSolarHistoryLines(28);
    res.json({ lastEntry });
  } catch (error) {
    console.error('[SOLAR HISTORY ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error reading solar history'
    });
  }
});

router.get('/ha/latest', authenticateToken, async (req, res) => {
  try {
    const data = await getLatestHaState();
    res.json(data);
  } catch (error) {
    console.error('[HA LATEST ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error reading HA state'
    });
  }
});

router.post('/ha/state', authenticateToken, async (req, res) => {
  try {
    const saved = await saveHaState(req.body || {});
    res.json({
      ok: true,
      saved
    });
  } catch (error) {
    console.error('[HA SAVE ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error saving HA state'
    });
  }
});

router.post('/ha/sensor', authenticateToken, async (req, res) => {
  try {
    const saved = await saveHaSensor(req.body || {});
    res.json({
      ok: true,
      saved
    });
  } catch (error) {
    console.error('[HA SENSOR SAVE ERROR]', error);
    res.status(400).json({
      ok: false,
      error: error.message || 'Error saving HA sensor'
    });
  }
});

router.get('/victron/data', authenticateToken, async (req, res) => {
  try {
    const data = await getVictronData();
    res.json(data);
  } catch (error) {
    console.error('[VICTRON ROUTE ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error fetching Victron data'
    });
  }
});


router.get('/growattData', authenticateToken, async (req, res) => {
  try {
    const data = await getGrowattData();
    res.json(data);
  } catch (error) {
    console.error('[GROWATT ROUTE ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error fetching Growatt data'
    });
  }
});


router.get('/cachedData', authenticateToken, async (req, res) => {
  try {
    const data = await getCombinedCachedData();
    res.json(data);
  } catch (error) {
    console.error('[CACHED DATA ROUTE ERROR]', error);
    res.status(500).json({
      ok: false,
      error: 'Error fetching cached data'
    });
  }
});

export default router;
