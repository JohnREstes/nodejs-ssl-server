import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export function signSessionToken(email) {
  return jwt.sign(
    { email },
    env.jwtSecret,
    { expiresIn: `${env.sessionDays}d` }
  );
}

export function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ ok: false, error: 'Missing token' });
  }

  try {
    req.user = jwt.verify(token, env.jwtSecret);
    next();
  } catch {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}
