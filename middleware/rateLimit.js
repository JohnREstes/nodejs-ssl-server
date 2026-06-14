import rateLimit from 'express-rate-limit';

const rateLimitMiddleware = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    error: 'Too many requests. Please try again shortly.'
  }
});

export default rateLimitMiddleware;
