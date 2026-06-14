import fs from 'fs/promises';
import path from 'path';

const DEFAULT_HISTORY_FILE = 'solar_data.txt';

export async function getLastSolarHistoryLines(numLines = 28) {
  const filePath = path.resolve(process.cwd(), DEFAULT_HISTORY_FILE);

  const data = await fs.readFile(filePath, 'utf8');

  const lines = data
    .trim()
    .split('\n')
    .filter(Boolean);

  return lines.slice(-numLines).join('\n');
}
