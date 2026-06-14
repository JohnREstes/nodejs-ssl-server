import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { getLastSolarHistoryLines } from '../services/solarHistoryService.js';

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

export default router;
