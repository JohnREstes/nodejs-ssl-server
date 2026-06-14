import Growatt from 'growatt';

const CACHE_TIMEOUT = 15 * 1000;

const growatt = new Growatt({});

let isLoggedIn = false;

let growattCache = {
  data: null,
  timestamp: 0
};

function getGrowattCredentials() {
  const username = process.env.GROWATT_USER;
  const password = process.env.GROWATT_PASSWORD;

  if (!username || !password) {
    throw new Error('Growatt credentials not set in environment');
  }

  return { username, password };
}

async function loginGrowatt() {
  if (isLoggedIn) return;

  const { username, password } = getGrowattCredentials();

  await growatt.login(username, password);

  isLoggedIn = true;
  console.log('[GROWATT] Login complete');
}

function extractGrowattData(allPlantData) {
  const yolandaPlant = allPlantData?.['4466'];
  const casaPlant = allPlantData?.['25328'];

  if (!yolandaPlant || !casaPlant) {
    throw new Error('Expected Growatt plants were not found');
  }

  const yolandaDevice = yolandaPlant.devices?.['UKDFBHG0GX'];
  const casaDevice1 = casaPlant.devices?.['XSK0CKS058'];
  const casaDevice2 = casaPlant.devices?.['XSK0CKS03A'];

  if (!yolandaDevice || !casaDevice1 || !casaDevice2) {
    throw new Error('Expected Growatt devices were not found');
  }

  return {
    yolandaData: yolandaDevice.statusData,
    casaMJData1: casaDevice1.statusData,
    casaMJData2: casaDevice2.statusData,

    yolandaDataTotal: yolandaDevice.totalData,
    casaMJData1Total: casaDevice1.totalData,
    casaMJData2Total: casaDevice2.totalData,

    weatherDataYolanda: yolandaPlant.weather?.data?.HeWeather6?.[0] || null,
    weatherDataCasaMJ: casaPlant.weather?.data?.HeWeather6?.[0] || null
  };
}

export async function getGrowattData({ forceRefresh = false } = {}) {
  const now = Date.now();

  if (
    !forceRefresh &&
    growattCache.data &&
    now - growattCache.timestamp < CACHE_TIMEOUT
  ) {
    return growattCache.data;
  }

  try {
    await loginGrowatt();

    const allPlantData = await growatt.getAllPlantData({});
    const data = extractGrowattData(allPlantData);

    growattCache = {
      data,
      timestamp: now
    };

    return data;
  } catch (error) {
    console.error('[GROWATT ERROR]', error.message);

    isLoggedIn = false;

    await loginGrowatt();

    const allPlantData = await growatt.getAllPlantData({});
    const data = extractGrowattData(allPlantData);

    growattCache = {
      data,
      timestamp: Date.now()
    };

    return data;
  }
}

export function getCachedGrowattData() {
  return growattCache.data;
}
