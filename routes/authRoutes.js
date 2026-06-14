import express from 'express';
import { isAllowedEmail, sendLoginCode, verifyLoginCode } from '../services/emailCodeService.js';
import { authenticateToken, signSessionToken } from '../middleware/auth.js';

const router = express.Router();

router.post('/send-code', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ ok: false, error: 'Email is required' });
    }

    await sendLoginCode(email);

    res.json({
      ok: true,
      message: 'If that email is allowed, a login code has been sent.'
    });
  } catch (error) {
    console.error('[AUTH SEND CODE ERROR]', error);
    res.status(500).json({ ok: false, error: 'Could not send login code' });
  }
});

router.post('/verify-code', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();

  if (!email || !code) {
    return res.status(400).json({ ok: false, error: 'Email and code are required' });
  }

  if (!isAllowedEmail(email)) {
    return res.status(401).json({ ok: false, error: 'Invalid code' });
  }

  const valid = verifyLoginCode(email, code);

  if (!valid) {
    return res.status(401).json({ ok: false, error: 'Invalid code' });
  }

  const token = signSessionToken(email);

  res.json({
    ok: true,
    token
  });
});

router.get('/me', authenticateToken, (req, res) => {
  res.json({
    ok: true,
    user: {
      email: req.user.email
    }
  });
});

export default router;
