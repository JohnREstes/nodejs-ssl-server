import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimitMiddleware from './middleware/rateLimit.js';
import authRoutes from './routes/authRoutes.js';
import solarRoutes from './routes/solarRoutes.js';

dotenv.config();

const app = express();

const allowedOrigins = [
  'https://johnetravels.com',
  'https://www.johnetravels.com',
  'http://localhost:8080',
  'http://localhost:5500'
];

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'OPTIONS']
}));

app.use(rateLimitMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/auth', authRoutes);
app.use('/api', solarRoutes);

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'johnetravels-solar-api',
    version: '2.0.0',
    time: new Date().toISOString()
  });
});

export default app;
