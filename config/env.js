import dotenv from 'dotenv';

dotenv.config();

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,

  jwtSecret: required('JWT_SECRET'),
  sessionDays: Number(process.env.SESSION_DAYS || 30),

  allowedLoginEmails: (process.env.ALLOWED_LOGIN_EMAILS || '')
    .split(',')
    .map(email => email.trim().toLowerCase())
    .filter(Boolean),

  awsRegion: process.env.AWS_REGION || 'us-east-1',
  loginEmailFrom: required('LOGIN_EMAIL_FROM'),
  loginCodeTtlMinutes: Number(process.env.LOGIN_CODE_TTL_MINUTES || 10),
  haIngestToken: process.env.HA_INGEST_TOKEN
};
