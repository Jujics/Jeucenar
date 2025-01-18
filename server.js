const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose(); 
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname)));
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
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
            if (await bcrypt.compare(Password, row.Password)) {
                // Save the current user's information to a JSON file
                const userData = {
                    users: [
                        {
                            Name: row.Name,
                            Level: row.Level,
                        },
                    ],
                };

                const filePath = 'currentUser.json';
                try {
                    fs.writeFileSync(filePath, JSON.stringify(userData, null, 2), 'utf-8');
                    console.log('Current user saved to JSON file.');
                } catch (fileErr) {
                    console.error('Error writing to JSON file:', fileErr);
                    return res.status(500).send('Error saving user data');
                }

                res.status(202).json({ message: 'Login successful', level: row.Level });
            } else {
                res.status(203).send('Wrong password');
            }
        } catch (err) {
            console.error(err);
            res.status(500).send('Error verifying password');
        }
    });
});

app.get('/current-user', (req, res) => {
    const filePath = 'currentUser.json';

    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf-8');
            res.status(200).json(JSON.parse(data));
        } else {
            res.status(404).json({ message: 'No current user data found.' });
        }
    } catch (err) {
        console.error('Error reading current user data:', err);
        res.status(500).json({ message: 'Error reading current user data.' });
    }
});

app.post('/change-lvl', (req, res) => {
    const { Name, Level } = req.body;

    // Validate inputs
    if (!Name || typeof Level !== 'number' || Level < 1) {
        return res.status(400).send('Invalid data. Name and a valid level are required.');
    }

    // Update the user's level in the database
    db.run('UPDATE UsersInfo SET Level = ? WHERE Name = ?', [Level, Name], function (err) {
        if (err) {
            console.error('Error updating user level:', err);
            return res.status(500).send('Error updating user level');
        }

        // Check if any rows were affected
        if (this.changes === 0) {
            return res.status(404).send('User not found');
        }

        res.status(200).send(`Level for user ${Name} updated to ${Level}`);
    });
});



app.listen(3000, () => {
    console.log('Server running on port 3000');
});
