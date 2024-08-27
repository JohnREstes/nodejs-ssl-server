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

dotenv.config();

const app = express();
const hostname = '127.0.0.1';
const port = 3000;

const CACHE_TIMEOUT = 30 * 1000; // 30 seconds in milliseconds

const secretKey = process.env.SECRET_KEY;
const hashedPassword = process.env.HASHED_PASSWORD;
const version = '1.4.3';

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

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        console.log('Password comparison successful');
        const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '30d' });
        res.json({ token });
    } else {
        console.log('Password comparison failed');
        res.status(401).json({ error: 'Invalid credentials' });
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
});

let victronCache = {
    data: null,
    timestamp: 0
};

var victronToken, idUserVictron, idSiteVictron;

async function fetchVictronData() {
    const currentTime = Date.now();

    // Check if cached data is valid
    if (victronCache.data && (currentTime - victronCache.timestamp) < CACHE_TIMEOUT) {
        return victronCache.data;
    }

    const usernameVic = process.env.USERNAME;
    const passwordVic = process.env.PASSWORD;

    try {
        await fetchData();
    } catch (error) {
        console.error(error);
        throw error;
    }

    async function fetchData() {
        if (!victronToken) {
            try {
                await get_login_token();
                await get_installations();
                await get_Chart();
            } catch (error) {
                console.error(error);
                throw error;
            }
        } else {
            try {
                await get_Chart();
            } catch (error) {
                victronToken = null;
                console.error(error);
                throw error;
            }
        }
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
            console.log(`Victron login Complete
                        User Id: ${idUserVictron}`)
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
            console.log(`Site Id: ${idSiteVictron}`)
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
                    timestamp: record.timestamp
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

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized - Token not provided' });
    }

    const tokenWithoutBearer = token.replace('Bearer ', '');

    jwt.verify(tokenWithoutBearer, secretKey, (err, user) => {
        if (err) {
            console.error('Token verification error:', err);
            return res.status(403).json({ error: 'Token is not valid or expired' });
        }

        req.user = user;
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
let lastRequestTime = Date.now();

async function loginGrowatt() {
  if (!isLoggedIn) {
    await growatt.login(process.env.GROWATT_USER, process.env.GROWATT_PASSWORD);
    isLoggedIn = true;
    console.log("Growatt login complete")
  }
}

async function logoutGrowatt() {
  if (isLoggedIn) {
    await growatt.logout();
    isLoggedIn = false;
    console.log("Growatt logoff complete")
  }
}

app.get('/api/growattData', authenticateToken, async (req, res) => {
    try {
        lastRequestTime = Date.now();
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

        return newGrowattData;
    } catch (e) {
        console.error('Error fetching Growatt data:', e);
        throw e;
    }
}

// Periodically check if logout is needed
setInterval(async () => {
  if (Date.now() - lastRequestTime > 2 * 60 * 1000) { // 2 minutes
    await logoutGrowatt();
  }
}, 30 * 1000); // Check every 30 seconds



// Function to write data to the file
const writeDataToFile = async () => {
    const timeZone = 'America/Cancun';
    const currentDate = moment().tz(timeZone).format('YYYY-MM-DD');
    
    try {
        const data1 = await fetchVictronData();
        const data2 = await getGrowattData();

        const towerDayTotal = data1[4]['formattedValue'] || 'Data not available';
        const yolandaDayTotal = data2.yolandaDataTotal.epvToday || 'Data not available';
        const casa1DayTotal = data2.casaMJData1Total.epvToday || 'Data not available';
        const casa2DayTotal = data2.casaMJData2Total.epvToday || 'Data not available';

        // Prepare the data to write to the file
        const data = `Date: ${currentDate}: [${towerDayTotal}, ${yolandaDayTotal}, ${casa1DayTotal}, ${casa2DayTotal}]\n`;

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

// Schedule the task to run at 7:30 PM Cancun Time
cron.schedule('58 17 * * *', async () => {
    await writeDataToFile();
}, {
    timezone: "America/Cancun"
});

// Function to get the last entry from the file
const getLastEntry = (filePath) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return reject(err);
            }

            // Split the file data by newlines to get an array of lines
            const lines = data.trim().split('\n');

            // Get the last line (most recent entry)
            const lastLine = lines[lines.length - 1];

            resolve(lastLine);
        });
    });
};

// Function to read the last entry from the file
const readSolarTotal = async () => {
    try {
        const lastEntry = await getLastEntry('solar_data.txt');
        return lastEntry;
    } catch (error) {
        console.error('Error reading file:', error);
    }
};

// Usage example: Run the task immediately for testing and then get the last entry
// (async () => {
//     await writeDataToFile(); // Manually run the task
//     const lastEntry = await readSolarTotal(); // Test read
//     console.log('Last Entry:', lastEntry);
// })();

// API endpoint to return the last entry from the file
app.get('/api/lastEntry', authenticateToken, async (req, res) => {
    try {
        const lastEntry = await getLastEntry('solar_data.txt');
        res.json({ lastEntry });
    } catch (error) {
        res.status(500).send('Error reading file');
    }
});