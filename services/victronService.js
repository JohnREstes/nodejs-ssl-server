let victronToken = null;
let idUserVictron = null;
let idSiteVictron = null;

let victronCache = {
  data: null,
  timestamp: 0
};

const CACHE_TIMEOUT = 15 * 1000;

const desiredAttributes = new Set([
  81,  // Voltage
  49,  // Current
  51,  // State of charge
  94,  // Daily Yield
  96,  // Yesterday's Daily Yield
  118, // Serial Number
  146, // Time to go
  442, // PV Power
  243  // Battery Power
]);

function getVictronCredentials() {
  const username = process.env.USERNAME;
  const password = process.env.PASSWORD;

  if (!username || !password) {
    throw new Error('Victron credentials not set in environment');
  }

  return { username, password };
}

async function loginToVictron() {
  const { username, password } = getVictronCredentials();

  const response = await fetch('https://vrmapi.victronenergy.com/v2/auth/login/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username,
      password,
      remember_me: true
    })
  });

  if (!response.ok) {
    throw new Error(`Victron login failed with status ${response.status}`);
  }

  const result = await response.json();

  if (!result.token || !result.idUser) {
    throw new Error('Victron login response missing token or user id');
  }

  victronToken = result.token;
  idUserVictron = result.idUser;

  console.log(`[VICTRON] Login complete. User Id: ${idUserVictron}`);
}

async function loadVictronInstallation() {
  if (!victronToken || !idUserVictron) {
    await loginToVictron();
  }

  const response = await fetch(
    `https://vrmapi.victronenergy.com/v2/users/${idUserVictron}/installations`,
    {
      method: 'GET',
      headers: {
        'X-Authorization': `Bearer ${victronToken}`
      }
    }
  );

  if (!response.ok) {
    throw new Error(`Victron installations failed with status ${response.status}`);
  }

  const result = await response.json();
  const idSite = result.records?.[0]?.idSite;

  if (!idSite) {
    throw new Error('No Victron installation found');
  }

  idSiteVictron = idSite;

  console.log(`[VICTRON] Site Id: ${idSiteVictron}`);
}

async function fetchVictronDiagnostics() {
  if (!victronToken || !idSiteVictron) {
    await loadVictronInstallation();
  }

  const response = await fetch(
    `https://vrmapi.victronenergy.com/v2/installations/${idSiteVictron}/diagnostics`,
    {
      method: 'GET',
      headers: {
        'X-Authorization': `Bearer ${victronToken}`
      }
    }
  );

  if (!response.ok) {
    throw new Error(`Victron diagnostics failed with status ${response.status}`);
  }

  const result = await response.json();

  if (!result.success) {
    throw new Error('Victron diagnostics response did not indicate success');
  }

  if (!result.records?.length) {
    throw new Error('Victron diagnostics records missing or empty');
  }

  return result.records
    .filter(record => desiredAttributes.has(record.idDataAttribute))
    .map(record => ({
      idDataAttribute: record.idDataAttribute,
      description: record.description,
      formattedValue: record.formattedValue,
      timestamp: record.timestamp,
      instance: record.instance
    }));
}

export async function getVictronData({ forceRefresh = false } = {}) {
  const now = Date.now();

  if (
    !forceRefresh &&
    victronCache.data &&
    now - victronCache.timestamp < CACHE_TIMEOUT
  ) {
    return victronCache.data;
  }

  try {
    const data = await fetchVictronDiagnostics();

    victronCache = {
      data,
      timestamp: now
    };

    return data;
  } catch (error) {
    console.error('[VICTRON ERROR]', error.message);

    // Reset auth once and retry on token/session issues.
    victronToken = null;
    idUserVictron = null;
    idSiteVictron = null;

    const data = await fetchVictronDiagnostics();

    victronCache = {
      data,
      timestamp: Date.now()
    };

    return data;
  }
}

export function getCachedVictronData() {
  return victronCache.data;
}
