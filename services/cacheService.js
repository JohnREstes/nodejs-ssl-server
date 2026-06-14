import { getVictronData } from './victronService.js';
import { getGrowattData } from './growattService.js';
import { getLatestHaState } from './haService.js';

let combinedCache = {
  data: null,
  timestamp: 0
};

const CACHE_TIMEOUT = 15 * 1000;

export async function getCombinedCachedData({ forceRefresh = false } = {}) {
  const now = Date.now();

  if (
    !forceRefresh &&
    combinedCache.data &&
    now - combinedCache.timestamp < CACHE_TIMEOUT
  ) {
    return combinedCache.data;
  }

  const [victron, growatt, ha] = await Promise.allSettled([
    getVictronData(),
    getGrowattData(),
    getLatestHaState()
  ]);

  const data = {
    victron: victron.status === 'fulfilled' ? victron.value : null,
    growatt: growatt.status === 'fulfilled' ? growatt.value : null,
    ha: ha.status === 'fulfilled' ? ha.value : null,
    errors: {}
  };

  if (victron.status === 'rejected') {
    data.errors.victron = victron.reason?.message || 'Victron error';
  }

  if (growatt.status === 'rejected') {
    data.errors.growatt = growatt.reason?.message || 'Growatt error';
  }

  if (ha.status === 'rejected') {
    data.errors.ha = ha.reason?.message || 'HA error';
  }

  combinedCache = {
    data,
    timestamp: now
  };

  return data;
}
