const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose(); 

const app = express();
app.use(express.json());
app.use(cors());

// Connect to SQLite database (it will create a new database file if it doesn't exist)
const db = new sqlite3.Database('data.db', (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        console.log("Connected to the SQLite database.");
    }
});

// Create the UsersInfo table if it doesn't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS UsersInfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT UNIQUE,
            Password TEXT,
            Level INTEGER
        )
    `);
});

// GET all users (for testing purposes)
app.get('/users', (req, res) => {
    db.all('SELECT * FROM UsersInfo', [], (err, rows) => {
        if (err) {
            res.status(500).send('Error retrieving users');
        } else {
            res.json(rows);
        }
    });
});

app.post('/users', async (req, res) => {
    const { Name, Password, Level = 1 } = req.body;

    // Check if all required fields are provided
    if (!Name || !Password) {
        return res.status(400).send('Name and Password are required.');
    }

    // Check if the user already exists
    db.get('SELECT * FROM UsersInfo WHERE Name = ?', [Name], async (err, row) => {
        if (row) {
            return res.status(400).send('Name already taken');
        }

        try {
            // Generate salt and hash the password
            const salt = await bcrypt.genSalt(10);  // Specify the number of rounds for generating salt
            const hashedPassword = await bcrypt.hash(Password, salt);  // Hash the password using the salt

            // Insert new user into the database
            db.run('INSERT INTO UsersInfo (Name, Password, Level) VALUES (?, ?, ?)', [Name, hashedPassword, Level], function (err) {
                if (err) {
                    return res.status(500).send('Error creating user');
                }
                res.status(201).send('User created');
            });
        } catch (err) {
            console.error('Error hashing password:', err);
            res.status(500).send('Error hashing password');
        }
    });
});

// POST login
app.post('/users/login', async (req, res) => {
    const { Name, Password } = req.body;

    // Find the user by name
    db.get('SELECT * FROM UsersInfo WHERE Name = ?', [Name], async (err, row) => {
        if (!row) {
            return res.status(400).send('Cannot find user');
        }

        try {
            // Compare the hashed password with the stored password
            if (await bcrypt.compare(Password, row.Password)) {
                res.status(202).send('Success');
            } else {
                res.status(203).send('Wrong password');
            }
        } catch (err) {
            console.error(err);
            res.status(500).send('Error verifying password');
        }
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
