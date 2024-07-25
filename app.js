import express from 'express';
import fetch from 'node-fetch';
import rateLimitMiddleware from './middlewares/ratelimit.js';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { google } from 'googleapis';

dotenv.config();

const app = express();
const hostname = '127.0.0.1';
const port = process.env.PORT || 3000;

const secretKey = process.env.SECRET_KEY;
const hashedPassword = process.env.HASHED_PASSWORD;
const version = '1.5.0';

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

// In-memory user storage for demonstration purposes
const users = [
    {
        id: 1,
        username: 'yolanda',
        password: hashedPassword,
    },
];

// Root endpoint
app.get('/', (req, res) => {
    res.send(`
        <html>
            <body>
                <h1 style="color:blue;text-align: center;margin-top: 100px;"> [Version ${version}]: Server is Running.</h1>
                <div style="position: fixed;top: 50%;left: 50%;transform: translate(-50%, -50%)">
                    <img src="https://picsum.photos/400/400?random=1">
                </div>
            </body>
        </html>
    `);
    console.log(`[Version ${version}]: New request => http://${hostname}:${port}${req.url}`);
});

// Login endpoint
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

// Authentication middleware
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

// Protected route
app.get('/protected-route', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route!' });
});

// Victron API endpoint
app.get('/api/victron/data', async (req, res) => {
    try {
        const data = await fetchAllData();
        res.json(data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Gmail integration
async function getAccessToken() {
    const oauth2Client = new google.auth.OAuth2(
        process.env.CLIENT_ID,
        process.env.CLIENT_SECRET,
        process.env.REDIRECT_URL
    );

    oauth2Client.setCredentials({
        refresh_token: process.env.REFRESH_TOKEN
    });

    try {
        const { token } = await oauth2Client.getAccessToken();
        console.log('Access Token:', token);
        return token;
    } catch (error) {
        console.error('Error fetching access token:', error);
        throw error;
    }
}

async function createTransporter() {
    const accessToken = await getAccessToken();
    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            type: 'OAuth2',
            user: process.env.EMAIL,
            clientId: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            refreshToken: process.env.REFRESH_TOKEN,
            accessToken: accessToken
        }
    });
}

app.post('/send-email', async (req, res) => {
    const transporter = await createTransporter();

    const mailOptions = {
        from: req.body.email,
        to: process.env.EMAIL,
        subject: 'New Contact Form Submission',
        text: `
        First Name: ${req.body.firstName}
        Last Name: ${req.body.lastName}
        Email: ${req.body.email}
        Phone: ${req.body.phone}
        Dates: ${req.body.dates}
        Travelers: ${req.body.travelers}
        Num. Rooms: ${req.body.rooms}
        Message: ${req.body.description}
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
        res.status(200).send('Email sent: ' + info.response);
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send(error.toString());
    }
});

// Start the server
app.listen(port, () => {
    console.log(`[Version ${version}]: Server running at http://${hostname}:${port}/`);
});

// Fetch Victron API data
async function fetchAllData() {
    const usernameVic = process.env.USERNAME;
    const passwordVic = process.env.PASSWORD;
    let data;

    try {
        await fetchData();
        return data;
    } catch (error) {
        console.error(error);
        throw error;
    }

    async function fetchData() {
        if (!token) {
            try {
                await get_login_token();
                await get_installations();
                data = await get_Chart();
            } catch (error) {
                console.error(error);
                throw error;
            }
        } else {
            try {
                data = await get_Chart();
            } catch (error) {
                token = null;
                console.error(error);
                throw error;
            }
        }
    }

    async function get_login_token() {
        const headers = { 'Content-Type': 'application/json' };
        const body = JSON.stringify({
            username: usernameVic,
            password: passwordVic,
            remember_me: 'true'
        });

        try {
            const response = await fetch("https://vrmapi.victronenergy.com/v2/auth/login/", { method: 'POST', headers, body });
            const result = await response.json();
            token = result.token;
            idUser = result.idUser;
        } catch (error) {
            console.log('Error fetching login token:', error);
            throw error;
        }
    }

    async function get_installations() {
        const headers = { 'X-Authorization': `Bearer ${token}` };

        try {
            const response = await fetch(`https://vrmapi.victronenergy.com/v2/users/${idUser}/installations`, { method: 'GET', headers });
            const result = await response.json();
            idSite = result.records[0].idSite;
        } catch (error) {
            console.log('Error fetching installations:', error);
            throw error;
        }
    }

    async function get_Chart() {
        const headers = { 'X-Authorization': `Bearer ${token}` };

        try {
            const response = await fetch(`https://vrmapi.victronenergy.com/v2/installations/${idSite}/diagnostics`, { method: 'GET', headers });
            const result = await response.json();

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
                442, // PV Power
            ]);

            const dataArray = result.records
                .filter(record => desiredAttributes.has(record.idDataAttribute))
                .map(record => ({
                    idDataAttribute: record.idDataAttribute,
                    description: record.description,
                    formattedValue: record.formattedValue,
                    timestamp: record.timestamp
                }));

            return dataArray;
        } catch (error) {
            console.log('Error fetching chart data:', error);
            throw error;
        }
    }
}
