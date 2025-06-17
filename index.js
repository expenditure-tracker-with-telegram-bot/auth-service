require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// --- Config ---
// The PORT will now default to 5005 as specified in your .env file
const PORT = process.env.PORT || 5005;
const SECRET_KEY = process.env.SECRET_KEY;
const MONGO_URI = process.env.MONGO_URI;

let db;
let usersCollection, transactionsCollection, auditCollection;

MongoClient.connect(MONGO_URI)
    .then(client => {
        console.log('Auth Service: Successfully connected to MongoDB.');
        db = client.db();
        usersCollection = db.collection('users');
        transactionsCollection = db.collection('transactions');
        auditCollection = db.collection('audit_logs');
    })
    .catch(error => {
        console.error('Failed to connect to MongoDB', error);
        process.exit(1); // Exit if DB connection fails
    });

app.post('/auth/signup', async (req, res) => {
    const { username, password, role = 'user' } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    try {
        const existingUser = await usersCollection.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await usersCollection.insertOne({
            username,
            password_hash: hashedPassword,
            role,
            created_at: new Date(),
        });
        res.status(201).json({ message: 'User created successfully', userId: result.insertedId });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    try {
        const user = await usersCollection.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const payload = { user_id: user._id.toString(), role: user.role };
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '24h' });
        await usersCollection.updateOne({ _id: user._id }, { $set: { last_login: new Date() } });
        res.status(200).json({
            message: 'Login successful',
            token: token,
            user: { id: user._id, username: user.username, role: user.role }
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

const isAdmin = (req, res, next) => {
    const userRole = req.headers['x-user-role'];
    if (userRole && userRole === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin access required.' });
    }
};

app.get('/admin/metrics/transactions', isAdmin, async (req, res) => {
    try {
        const now = new Date();
        const start_date = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
        const pipeline = [
            { '$match': { 'timestamp': { '$gte': start_date } } },
            {
                '$group': {
                    '_id': { '$dateToString': { 'format': '%Y-%m-%d', 'date': '$timestamp' } },
                    'count': { '$sum': 1 },
                    'total_amount': { '$sum': '$amount' }
                }
            },
            { '$sort': { '_id': 1 } }
        ];
        const daily_stats = await transactionsCollection.aggregate(pipeline).toArray();
        res.status(200).json({ period: '30d', daily_breakdown: daily_stats });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/admin/metrics/users', isAdmin, async (req, res) => {
    try {
        const twentyFourHoursAgo = new Date(new Date().getTime() - (24 * 60 * 60 * 1000));
        const active_users = await usersCollection.countDocuments({ last_login: { $gte: twentyFourHoursAgo } });
        const total_users = await usersCollection.countDocuments({});
        res.status(200).json({ total_users, active_users_24h: active_users });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/audit-logs', isAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const logs = await auditCollection.find().sort({ timestamp: -1 }).limit(limit).toArray();
        res.status(200).json(logs);
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.listen(PORT, () => {
    console.log(`Auth & Admin service running on port ${PORT}`);
});