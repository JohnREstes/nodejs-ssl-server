import crypto from 'crypto';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { env } from '../config/env.js';

const ses = new SESClient({ region: env.awsRegion });

const codeStore = new Map();

function normalizeEmail(email = '') {
  return email.trim().toLowerCase();
}

function generateCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

export function isAllowedEmail(email) {
  return env.allowedLoginEmails.includes(normalizeEmail(email));
}

export async function sendLoginCode(email) {
  const normalizedEmail = normalizeEmail(email);

  if (!isAllowedEmail(normalizedEmail)) {
    return { ok: true };
  }

  const code = generateCode();
  const expiresAt = Date.now() + env.loginCodeTtlMinutes * 60 * 1000;

  codeStore.set(normalizedEmail, {
    codeHash: hashCode(code),
    expiresAt,
    attempts: 0
  });

  const command = new SendEmailCommand({
    Source: env.loginEmailFrom,
    Destination: {
      ToAddresses: [normalizedEmail]
    },
    Message: {
      Subject: {
        Data: 'Your JohnETravels login code'
      },
      Body: {
        Text: {
          Data: `Your login code is ${code}. It expires in ${env.loginCodeTtlMinutes} minutes.`
        }
      }
    }
  });

  await ses.send(command);

  return { ok: true };
}

export function verifyLoginCode(email, code) {
  const normalizedEmail = normalizeEmail(email);
  const record = codeStore.get(normalizedEmail);

  if (!record) return false;
  if (Date.now() > record.expiresAt) {
    codeStore.delete(normalizedEmail);
    return false;
  }

  record.attempts += 1;
  if (record.attempts > 5) {
    codeStore.delete(normalizedEmail);
    return false;
  }

  const valid = record.codeHash === hashCode(String(code).trim());

  if (valid) {
    codeStore.delete(normalizedEmail);
  }

  return valid;
}
