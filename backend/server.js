const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB Limit
    fileFilter: (req, file, cb) => {
        // Allowed extensions
        const fileTypes = /jpeg|jpg|png|pdf/;
        const extName = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimeType = fileTypes.test(file.mimetype);

        if (extName && mimeType) {
            return cb(null, true);
        } else {
            cb(new Error('Only images (jpeg, jpg, png) and PDFs are allowed!'));
        }
    }
});

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
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
    const { username, password, role } = req.body;

    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM Users WHERE username = @username');

        const user = result.recordset[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (user.Role !== role) {
            return res.status(403).json({ message: 'Invalid role selection' });
        }

        const isMatch = await bcrypt.compare(password, user.PasswordHash);
        if (isMatch) {
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

app.post('/api/v1/claim', authenticateToken, upload.single('receipt'), async (req, res) => {
    const userId = req.user.id; // from the JWT token
    const { amount, description, category } = req.body;
    const receiptPath = req.file ? req.file.path : null;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .input('amount', sql.Decimal(18, 2), amount)
            .input('description', sql.VarChar, description)
            .input('category', sql.VarChar, category)
            .input('receiptPath', sql.VarChar, receiptPath)
            .query(`INSERT INTO ReimbursementClaims (UserId, Amount, Description, Category, ReceiptPath) VALUES (@userId, @amount, @description, @category, @receiptPath)`);
        res.status(201).json({ message: 'Claim submitted successfully' });
    }
    catch (err) {
        console.error('Claim submission error:', err);
        res.status(500).json({ message: 'Failed to submit claim' });
    }
})

app.get('/api/v1/claims/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query('SELECT * FROM ReimbursementClaims WHERE UserId = @userId');
        return res.json(result.recordset);
    }
    catch (err) {
        console.error('Error fetching claims:', err);
        return res.status(500).json({ message: 'Failed to fetch claims' });
    }
})

app.patch('/api/v1/claim/:claimId', authenticateToken, async (req, res) => {
    const { claimId } = req.params;
    const { status, comment } = req.body;
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('claimId', sql.Int, claimId)
            .input('status', sql.VarChar, status)
            .input('comment', sql.VarChar, comment || null)
            .query('UPDATE ReimbursementClaims SET Status = @status, ManagerComment = @comment, UpdatedDate = GETDATE() WHERE ClaimID = @claimId');
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

app.delete('/api/v1/claim/:claimId', authenticateToken, async (req, res) => {
    // SECURITY: Only managers can delete
    if (req.user.role !== 'Manager' && req.user.role !== 'Admin') {
        return res.status(403).json({ message: "Unauthorized to delete records" });
    }

    const { claimId } = req.params;

    try {
        const pool = await sql.connect(dbConfig);
        await pool.request()
            .input('claimId', sql.Int, claimId)
            .query('DELETE FROM ReimbursementClaims WHERE ClaimID = @claimId');

        res.json({ message: "Record deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Delete failed" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log("Server running on port" + PORT);
})