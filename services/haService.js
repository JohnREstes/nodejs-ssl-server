import fs from 'fs/promises';
import path from 'path';

const HA_DATA_FILE = path.resolve(process.cwd(), 'data/ha_state.json');

export async function getLatestHaState() {
  try {
    const data = await fs.readFile(HA_DATA_FILE, 'utf8');
    return JSON.parse(data || '{}');
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

export async function saveHaState(data) {
  await fs.mkdir(path.dirname(HA_DATA_FILE), { recursive: true });
  await fs.writeFile(HA_DATA_FILE, JSON.stringify(data, null, 2));
  return data;
}
