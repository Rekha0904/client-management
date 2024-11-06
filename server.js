const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Rekhagowda@0904',
    database: 'user_management'
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL connected...');
});

// Register route
app.post('/register', (req, res) => {
    const { name, email, password, repeatPassword } = req.body;

    if (password !== repeatPassword) {
        return res.status(400).send('Passwords do not match');
    }

    const hashedPassword = bcrypt.hashSync(password, 8);

    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).send('Error registering user');

        const userId = result.insertId; // Get the newly inserted user's ID

        // Fetch the newly inserted user data
        const fetchQuery = 'SELECT id, name, email, created_at FROM users WHERE id = ?';
        db.query(fetchQuery, [userId], (fetchErr, fetchResults) => {
            if (fetchErr) return res.status(500).send('Error fetching user data');
            res.status(200).send(fetchResults[0]); // Return the newly inserted user data
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) return res.status(500).send('Error on the server');
        if (results.length === 0) return res.status(404).send('No user found');

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        const success = passwordIsValid;

        // Log the login attempt
        const logQuery = 'INSERT INTO logins (user_id, success) VALUES (?, ?)';
        db.query(logQuery, [user.id, success], (logErr, logResult) => {
            if (logErr) console.error('Error logging login attempt', logErr);

            const loginId = logResult.insertId; // Get the newly inserted login attempt ID

            // Fetch the newly inserted login data
            const fetchLoginQuery = 'SELECT id, user_id, login_time, success FROM logins WHERE id = ?';
            db.query(fetchLoginQuery, [loginId], (fetchLoginErr, fetchLoginResults) => {
                if (fetchLoginErr) return res.status(500).send('Error fetching login data');
                
                // Generate JWT token if login is successful
                let token = null;
                if (passwordIsValid) {
                    token = jwt.sign({ id: user.id }, 'supersecret', { expiresIn: 86400 });
                }

                res.status(200).send({
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email
                    },
                    login: fetchLoginResults[0],
                    token
                });
            });
        });

        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    });
});

// Schedule meeting route
app.post('/schedule-meeting', (req, res) => {
    const { userId, topic, numberOfPeople, datetime } = req.body;
    const query = 'INSERT INTO meetings (user_id, topic, number_of_people, datetime) VALUES (?, ?, ?, ?)';
    db.query(query, [userId, topic, numberOfPeople, datetime], (err, result) => {
        if (err) return res.status(500).send('Error scheduling meeting');

        const meetingId = result.insertId; // Get the newly inserted meeting ID

        // Fetch the newly inserted meeting data
        const fetchQuery = 'SELECT id, user_id, topic, number_of_people, datetime, created_at FROM meetings WHERE id = ?';
        db.query(fetchQuery, [meetingId], (fetchErr, fetchResults) => {
            if (fetchErr) return res.status(500).send('Error fetching meeting data');
            res.status(200).send(fetchResults[0]); // Return the newly inserted meeting data
        });
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`Port ${port} is already in use. Trying another port...`);
        port = 3001;  // You can increment this number as needed.
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } else {
        throw err;
    }
});