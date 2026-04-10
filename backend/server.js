const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

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

const authenticateToken = (req,res,next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token){
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = decoded;
        next();
    });

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

app.post('/api/v1/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            // .input('password', sql.VarChar, password)
            .query('SELECT * FROM Users WHERE username = @username');

        const user = result.recordset[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (user.PasswordHash == password) {
            const token = jwt.sign({
                id: user.UserID,
                username: user.Username,
                role: user.Role
            }, process.env.JWT_SECRET, { expiresIn: '1h' });

            return res.json({ message: 'Login successful', token, user: { id: user.UserID, username: user.Username, role: user.Role } });
        }
        else {
            return res.status(401).json({ message: 'Invalid Password' });
        }

    }
    catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.post('/api/v1/claim',authenticateToken, async (req, res) => {
    const { userId, amount, description, category } = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .input('amount', sql.Decimal(18, 2), amount)
            .input('description', sql.VarChar, description)
            .input('category', sql.VarChar, category)
            .query(`INSERT INTO ReimbursementClaims (UserId, Amount, Description, Category) VALUES (@userId, @amount, @description, @category)`);
        res.status(201).json({ message: 'Claim submitted successfully' });
    }
    catch (err) {
        console.error('Claim submission error:', err);
        res.status(500).json({ message: 'Failed to submit claim' });
    }
})

app.get('/api/v1/claims/:userId',authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try{
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query('SELECT * FROM ReimbursementClaims WHERE UserId = @userId');
        res.json(result.recordset);
    }
    catch(err){
        console.error('Error fetching claims:', err);
        res.status(500).json({ message: 'Failed to fetch claims' });
    }
})

app.patch('/api/v1/claim/:claimId', authenticateToken, async(req, res)=> {
    const {claimId} = req.params;
    const {status} = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('claimId', sql.Int, claimId)
            .input('status', sql.VarChar, status)
            .query('UPDATE ReimbursementClaims SET Status = @status WHERE ClaimID = @claimId');
        return res.json({ message: 'Claim status updated' });
    } catch (error) {
        console.error('Error updating claim status:', error);
        return res.status(500).json({ message: 'Failed to update claim status' });
    }
})

app.get('/api/v1/claims/all/pending', authenticateToken, async (req, res) => {
    // Security check: Ensure only Managers can see the full queue
    if (req.user.role !== 'Manager' && req.user.role !== 'Admin') {
        return res.status(403).json({ message: "Access Denied" });
    }

    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .query("SELECT * FROM ReimbursementClaims WHERE Status = 'Pending' ORDER BY SubmittedDate ASC");
        
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch pending queue" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server running on port" + PORT);
})