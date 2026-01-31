import express from 'express';
import fetch from 'node-fetch';
import rateLimitMiddleware from './middlewares/ratelimit.js';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import fs from 'fs'
import cron from 'node-cron';
import moment from 'moment-timezone';
import Growatt from 'growatt';
import mongoose from 'mongoose';

dotenv.config();

if (process.env.MONGO_URI) {
  mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));
} else {
  console.warn('MongoDB disabled: MONGO_URI not set');
}

const app = express();
const hostname = '127.0.0.1';
const port = 3000;

const CACHE_TIMEOUT = 15 * 1000; // 15 seconds in milliseconds

const secretKey = process.env.SECRET_KEY;
const hashedPassword = process.env.HASHED_PASSWORD;
const version = '2.0.1';

const user = null;

const corsOptions = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    optionsSuccessStatus: 204,
    credentials: true,
    allowedHeaders: 'Content-Type, Authorization',
};

app.use(cors(corsOptions));
app.use(rateLimitMiddleware);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const users = [
    {
      id: 1,
      username: 'yolanda',
      password: hashedPassword,
    },
];

app.get('/', (req, res) => {
    res.send(`<html>
                <body>
                    <h1 style="color:blue;text-align: center;margin-top: 100px;"> [Version ${version}]: Server is Running.</h1>
                    <div style="position: fixed;top: 50%;left: 50%;transform: translate(-50%, -50%)">
                        <img src="https://picsum.photos/400/400?random=1">
                    </div>
                </body>
               </html>`);
    console.log(`[Version ${version}]: New request => http://${hostname}:${port}` + req.url);
});

import User from './models/User.js';

app.post('/register', async (req, res) => {
    try {
        const { username, password, victronUsername, victronPassword, growattUsername, growattPassword, haLongTermKey } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Username already exists' });

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user to MongoDB
        const newUser = new User({ 
            username, 
            password: hashedPassword, 
            victronUsername, 
            victronPassword, 
            growattUsername, 
            growattPassword, 
            haLongTermKey 
        });
        await newUser.save();

        res.json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        user = await User.findOne({ username });

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        // Compare passwords
        if (bcrypt.compareSync(password, user.password)) {
            console.log('Password comparison successful');
            const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '30d' });
            res.json({ token });
        } else {
            console.log('Password comparison failed');
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/protected-route', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route!' });
});

app.get('/api/victron/data', authenticateToken, async (req, res) => {
    try {
        const data = await fetchVictronData();
        res.json(data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(port, () => {
    console.log(`[Version ${version}]: Server running at http://${hostname}:${port}/`);
      // Initial data load on server startup
  checkActiveHours();
  updateCachedData();
});

var cachedData = {
    growatt: null,
    victron: null
  };
  
  // A flag to track active hours (0500 - 2300)
  let isActiveHours = false;
  
  // Function to check if it's within active hours (0500 - 2300)
  function checkActiveHours() {
    const now = new Date();
    const currentHour = now.getUTCHours() - 5;  // Adjust based on timezone
  
    // Set to active if it's within 0500 - 2300
    isActiveHours = (currentHour >= 5 && currentHour < 23);
  }
  
  // Function to update cached data
  async function updateCachedData() {
    if (!isActiveHours) return;
    try {
        // Fetch and cache Growatt data (internal in called function)
        await getGrowattData();
        // Fetch and cache Victron data (internal in called function)
        await fetchVictronData();
    } catch (error) {
        console.error('Error fetching data:', error);
    }
  }
  
  // Schedule data updates every 2.5 minutes (150,000 milliseconds)
  setInterval(() => {
    checkActiveHours();
    updateCachedData();
  }, 150000);  // 2.5 minutes
  
  // Endpoint to serve cached data
  app.get('/api/cachedData', authenticateToken, (req, res) => {
    res.json({
      growatt: cachedData.growatt,
      victron: cachedData.victron
    });
  });


var victronToken, idUserVictron, idSiteVictron;

async function fetchVictronData() {
    let victronCache = {
        data: null,
        timestamp: 0
    };
    const currentTime = Date.now();

    // Check if cached data is valid
    if (victronCache.data && (currentTime - victronCache.timestamp) < CACHE_TIMEOUT) {
        cachedData.victron = victronCache.data;
        return victronCache.data;
    }

        const usernameVic = process.env.USERNAME;
        const passwordVic = process.env.PASSWORD;

        if (!usernameVic || !passwordVic) {
            throw new Error('Victron credentials not set in environment');
        }


    return await fetchData()

    async function fetchData() {
        var victronData = null;
        if (!victronToken) {
            try {
                await get_login_token();
                await get_installations();
                victronData = await get_Chart();
            } catch (error) {
                console.error(error);
                throw error;
            }
        } else {
            try {
                victronData = await get_Chart();
            } catch (error) {
                victronToken = null;
                console.error(error);
                throw error;
            }
        }
        cachedData.victron = victronData;
        return victronData
    }

    async function get_login_token() {
        const myHeaders = new Headers();
        myHeaders.append("Content-Type", "application/json");

        const raw = JSON.stringify({
            "username": usernameVic,
            "password": passwordVic,
            "remember_me": "true"
        });

        const requestOptions = {
            method: 'POST',
            headers: myHeaders,
            body: raw,
            redirect: 'follow'
        };

        try {
            const response = await fetch("https://vrmapi.victronenergy.com/v2/auth/login/", requestOptions);
            const result = await response.json();
            victronToken = result.token;
            idUserVictron = result.idUser;
            console.log(`Victron login Complete\n   User Id: ${idUserVictron}`);
        } catch (error) {
            console.log('error', error);
            throw error;
        }
    }

    async function get_installations() {
        const headers = { 'X-Authorization': `Bearer ${victronToken}` };

        const requestOptions = {
            method: 'GET',
            headers: headers,
            redirect: 'follow'
        };

        try {
            const response = await fetch(`https://vrmapi.victronenergy.com/v2/users/${idUserVictron}/installations`, requestOptions);
            const result = await response.json();
            idSiteVictron = result.records[0].idSite;
            console.log(`   Site Id: ${idSiteVictron}`)
        } catch (error) {
            console.log('error', error);
            throw error;
        }
    }

    async function get_Chart() {
        const headers = { 'X-Authorization': `Bearer ${victronToken}` };

        const requestOptions = {
            method: 'GET',
            headers: headers,
            redirect: 'follow'
        };

        try {
            const response = await fetch(`https://vrmapi.victronenergy.com/v2/installations/${idSiteVictron}/diagnostics`, requestOptions);
            const result = await response.json();
            //fs.writeFileSync('plantData.json', JSON.stringify(result, null, 2));
            //console.log('Data written to plantData.json');

            if (!result.success) {
                throw new Error('The returned response did not indicate success.');
            }

            if (!result.records?.length) {
                throw new Error('The response data array is either missing or empty.');
            }

            const desiredAttributes = new Set([
                81, // Voltage
                49, // Current
                51, // State of charge
                94, // Daily Yield
                96, // Yesterday's Daily Yield
                118, //Serial Number
                146, //TimeToGo
                442, // PV Power
                243, //Battery Power
            ]);

            const newVictronData = result.records
                .filter(record => desiredAttributes.has(record.idDataAttribute))
                .map(record => ({
                    idDataAttribute: record.idDataAttribute,
                    description: record.description,
                    formattedValue: record.formattedValue,
                    timestamp: record.timestamp,
                    instance: record.instance
                }));

            // Update cache with new data and timestamp
            victronCache.data = newVictronData;
            victronCache.timestamp = currentTime;    
            
            return newVictronData;
        } catch (error) {
            console.log('error', error);
            throw error;
        }
    }
}

function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const tokenWithoutBearer = token.replace('Bearer ', '');

    // ✅ Home Assistant system token
    if (tokenWithoutBearer === process.env.HA_LONG_TERM_TOKEN) {
        req.user = { id: 'home-assistant', role: 'system' };
        return next();
    }

    jwt.verify(tokenWithoutBearer, secretKey, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
}



// Create an SES client
const sesClient = new SESClient({
    region: process.env.REGION,
    credentials: {
        accessKeyId: process.env.ACCESS_KEY,
        secretAccessKey: process.env.SECRET_ACCESS_KEY
    }
});

const sendEmail = async (recipientEmail, req) => {
    // Create sendEmail params
    const params = {
        Source: process.env.SES_SENDER,
        Destination: {
            ToAddresses: [
                recipientEmail,
            ],
        },
        Message: {
            Body: {
                Html: {
                    Charset: "UTF-8",
                    Data: `
                    First Name: ${req.body.firstName}
                    Last Name: ${req.body.lastName}
                    Email: ${req.body.email}
                    Phone: ${req.body.phone}
                    Dates: ${req.body.dates}
                    Travelers: ${req.body.travelers}
                    Num. Rooms: ${req.body.rooms}
                    Message: ${req.body.description}
                    `,
                },
                Text: {
                    Charset: "UTF-8",
                    Data: "TEXT_FORMAT_BODY",
                },
            },
            Subject: {
                Charset: "UTF-8",
                Data: `New Contact Form`,
            },
        },
        ReplyToAddresses: [
            process.env.SES_SENDER,
        ],
    };

    try {
        const command = new SendEmailCommand(params);
        const res = await sesClient.send(command);
        console.log("Email Sent: ", res);
    } catch (error) {
        console.error("Error sending email: ", error);
    }
};

app.post('/send-email', async (req, res) => {
    try {
        const data = await sendEmail('support@johnetravels.com', req);;
        res.json(data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


let growatt = new Growatt({});
let isLoggedIn = false;

async function loginGrowatt() {
    if (isLoggedIn) return;
    await growatt.login(
        process.env.GROWATT_USER,
        process.env.GROWATT_PASSWORD
        );
    isLoggedIn = true;
    console.log("Growatt login complete")
    return;
}

async function logoutGrowatt() {
    if (!isLoggedIn) return;
    await growatt.logout();
    isLoggedIn = false;
    console.log("Growatt logoff complete")
}

app.get('/api/growattData', authenticateToken, async (req, res) => {
    try {
        const data = await getGrowattData();
        res.json(data);
    } catch (e) {
        res.status(500).send('Internal Server Error');
    }
});

let growattCache = {
    data: null,
    timestamp: 0
};

async function getGrowattData() {

    const currentTime = Date.now();

    // Check if cached data is valid
    if (growattCache.data && (currentTime - growattCache.timestamp) < CACHE_TIMEOUT) {
        cachedData.growatt = growattCache.data;
        return growattCache.data;
    }

    try {
        await loginGrowatt();

        let getAllPlantData = await growatt.getAllPlantData({});

        // Extract data
        const yolandaData = getAllPlantData['4466']['devices']['UKDFBHG0GX']['statusData'];
        const casaMJData1 = getAllPlantData['25328']['devices']['XSK0CKS058']['statusData'];
        const casaMJData2 = getAllPlantData['25328']['devices']['XSK0CKS03A']['statusData'];
        const yolandaDataTotal = getAllPlantData['4466']['devices']['UKDFBHG0GX']['totalData'];
        const casaMJData1Total = getAllPlantData['25328']['devices']['XSK0CKS058']['totalData'];
        const casaMJData2Total = getAllPlantData['25328']['devices']['XSK0CKS03A']['totalData'];
        const weatherDataYolanda = getAllPlantData['4466']['weather']['data']['HeWeather6'][0];
        const weatherDataCasaMJ = getAllPlantData['25328']['weather']['data']['HeWeather6'][0];

        const newGrowattData = {
            yolandaData,
            casaMJData1,
            casaMJData2,
            yolandaDataTotal,
            casaMJData1Total,
            casaMJData2Total,
            weatherDataYolanda,
            weatherDataCasaMJ
        };

        // Update cache with new data and timestamp
        growattCache.data = newGrowattData;
        growattCache.timestamp = currentTime;

        cachedData.growatt = newGrowattData;
        return newGrowattData;
    } catch (e) {
        console.error('Error fetching Growatt data:', e);
        isLoggedIn = false;
        throw e;
    }
}

// Periodically check if logout is needed
// setInterval(async () => {
//   if (Date.now() - lastRequestTime > 5 * 60 * 1000) { // 5 minutes
//     await logoutGrowatt();
//   }
// }, 5 * 60 * 1000); // Check every 5 Minutes

// Function to write data to the file
const writeDataToFile = async () => {
    const timeZone = 'America/Cancun';
    const currentDate = moment().tz(timeZone).format('YYYY-MM-DD');

    try {
        const data1 = await fetchVictronData();
        const data2 = await getGrowattData();

        // Step 1: Find instances for the required serial numbers
        const towerSerial = 'HQ2131HZ2ZV';
        const pergolaSerial = 'HQ2342AE2NT';

        const towerInstance = data1.find(
            (item) =>
                item.idDataAttribute === 118 && item.formattedValue === towerSerial
        )?.instance;

        const pergolaInstance = data1.find(
            (item) =>
                item.idDataAttribute === 118 && item.formattedValue === pergolaSerial
        )?.instance;

        // Step 2: Use instances to get the "Yield today" values
        const towerDayTotal = data1.find(
            (item) =>
                item.idDataAttribute === 94 && item.instance === towerInstance
        )?.formattedValue || 'Data not available';

        const pergolaDayTotal = data1.find(
            (item) =>
                item.idDataAttribute === 94 && item.instance === pergolaInstance
        )?.formattedValue || 'Data not available';

        // Step 3: Fetch Growatt data
        const yolandaDayTotal = data2.yolandaDataTotal.epvToday || 'Data not available';
        const casa1DayTotal = data2.casaMJData1Total.epvToday || 'Data not available';
        const casa2DayTotal = data2.casaMJData2Total.epvToday || 'Data not available';

        // Prepare the data to write to the file
        const data = `Date: ${currentDate}: [${towerDayTotal}, ${pergolaDayTotal}, ${yolandaDayTotal}, ${casa1DayTotal}, ${casa2DayTotal}]\n`;

        // Write the values to a file
        fs.appendFile('solar_data.txt', data, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
            } else {
                console.log('Data written to file successfully.');
            }
        });
    } catch (error) {
        console.error('Error running methods:', error);
    }
};

// Schedule the task to run at 5:58 PM Cancun Time
cron.schedule('58 17 * * *', async () => { //58 17 * * *
    await writeDataToFile();
}, {
    timezone: "America/Cancun"
});

// Function to get the last 28 lines from the file
const getLastLines = (filePath, numLines = 28) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return reject(err);
            }

            // Split the file data by newlines to get an array of lines
            const lines = data.trim().split('\n');

            // Extract the last 'numLines' lines (or fewer if the file has fewer lines)
            const lastLines = lines.slice(-numLines);

            resolve(lastLines.join('\n'));  // Join back to a string for easier response
        });
    });
};

app.get('/api/lastEntry', authenticateToken, async (req, res) => {
    try {
        const lastEntry = await getLastLines('solar_data.txt', 28);
        res.json({ lastEntry });
    } catch (error) {
        res.status(500).send('Error reading file');
    }
});

app.post('/api/ha/sensor', authenticateToken, async (req, res) => {
    console.log('[HA INGEST RAW]', JSON.stringify(req.body, null, 2));
    try {
        const {
            entity_id,
            state,
            attributes,
            last_changed,
            timestamp
        } = req.body;

        if (!entity_id) {
            return res.status(400).json({ error: 'Missing entity_id' });
        }

        console.log('[HA]', entity_id, state);

        // Example: store latest HA data in memory
        if (!cachedData.homeAssistant) {
            cachedData.homeAssistant = {};
        }

        cachedData.homeAssistant[entity_id] = {
            state,
            attributes,
            last_changed,
            timestamp: timestamp || new Date().toISOString()
        };

        // 🔁 OPTIONAL: trigger logic
        // await evaluateAutomation(entity_id, state);

        res.json({ status: 'ok' });
    } catch (err) {
        console.error('HA ingest error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
