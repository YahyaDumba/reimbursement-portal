const express = require('express');
const sql = require('mssql');
require('dotenv').config();

const app = express();
app.use(express.json());

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
}

console.log("Checking DB Server Variable:", process.env.DB_SERVER);
sql.connect(dbConfig).then(pool => {
    if (pool.connected)
        console.log('Connected to SQL Server');
}).catch(err => {
    console.error('Database connection failed:', err);
    process.exit(1);
})

app.get('/api/v1/status', (req, res) => {
    res.json({ message: 'Welcome to the Reimbursement Portal API' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server running on port" + PORT);
})

app.post('/api/v1/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .input('password', sql.VarChar, password)
            .query('SELECT * FROM Users WHERE username = @username AND password = @password');

        const user = result.recordset[0];
        if(!user) {
            res.status(401).json({message: 'Invalid credentials'});
        }

        if(user.PasswordHash == password) {
            res.json({message: 'Login successful', user: { id: user.Id, username: user.Username, role: user.Role }});
        }
        else {
            res.status(401).json({message: 'Invalid Password'});
        }

    }
    catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
})