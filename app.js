const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const multer = require('multer'); // Add multer for handling file uploads
const fs = require('fs');
const secret = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable for JWT secret

const app = express();
const port = 3000;
const dbPath = path.join(__dirname, 'main.db');
const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable for JWT secret

let db; // Database instance

// Initialize database
async function initializeDatabase() {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });

        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullName TEXT,
                Email TEXT UNIQUE,
                Password TEXT,
                otp INTEGER,
                otp_expiry INTEGER,
                verification BOOLEAN DEFAULT FALSE,
                resetToken TEXT,
                resetTokenExpiry INTEGER
            );
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER,
                title TEXT,
                content TEXT,
                mediaUrl TEXT,
                mediaType TEXT,
                createdAt INTEGER,
                updatedAt INTEGER,
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                postId INTEGER,
                userId INTEGER,
                FOREIGN KEY (postId) REFERENCES posts(id),
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS dislikes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                postId INTEGER,
                userId INTEGER,
                FOREIGN KEY (postId) REFERENCES posts(id),
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                postId INTEGER,
                userId INTEGER,
                comment TEXT,
                createdAt INTEGER,
                FOREIGN KEY (postId) REFERENCES posts(id),
                FOREIGN KEY (userId) REFERENCES users(id)
            );
        `);

        console.log('Database initialized');
    } catch (error) {
        console.error('Failed to initialize the database', error);
        process.exit(1); // Exit the process if database initialization fails
    }
}

// Call initializeDatabase at the start
initializeDatabase();

app.use(express.static(path.join(__dirname, 'public')));
app.use('/login', express.static(path.join(__dirname, 'public', 'login.html')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup.html')));
app.use('/verify/otp', express.static(path.join(__dirname, 'public', 'verify.html')));
app.use('/dashboard/:id', express.static(path.join(__dirname, 'public', 'dashboard.html')));
app.use('/post/:id', express.static(path.join(__dirname, 'public', 'post.html')));
app.use('/profile/:id', express.static(path.join(__dirname, 'public', 'profile.html')));
app.use(bodyParser.json());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Set up multer for file uploads
const upload = multer({ dest: 'uploads/' });

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'hsbl480085@gmail.com',
        pass: 'lwqz khjb nwzg cyoj'
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// User signup
app.post('/signup', async (req, res) => {
    const { fullName, Email, Password } = req.body;

    if (!fullName || !Email || !Password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const existingUser = await db.get('SELECT * FROM users WHERE Email = ?', [Email]);

        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(Password, 10);
        const otp = crypto.randomInt(100000, 999999); // Generate 6-digit OTP

        const result = await db.run('INSERT INTO users (fullName, Email, Password, otp, otp_expiry, verification) VALUES (?, ?, ?, ?, ?, ?)', [
            fullName,
            Email,
            hashedPassword,
            otp,
            Date.now() + 15 * 60 * 1000, // OTP expires in 15 minutes
            false
        ]);

        const userId = result.lastID;

        await transporter.sendMail({
            from: 'no-reply@gyan.com',
            to: Email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`
        });

        // Send userId in the response for redirection
        res.json({ userId });
    } catch (error) {
        console.error('Signup failed', error);
        res.status(500).json({ error: 'Signup failed' });
    }
});

// OTP verification
app.post('/verify/otp', async (req, res) => {
    const { otp } = req.body;

    if (!otp) {
        return res.status(400).json({ error: 'OTP is required' });
    }

    try {
        const user = await db.get('SELECT * FROM users WHERE otp = ? AND otp_expiry > ? ', [otp, Date.now()]);

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        await db.run('UPDATE users SET verification = true WHERE id = ?', [user.id]);

        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ message: 'OTP verified successfully!', token });
    } catch (error) {
        console.error('OTP verification failed', error);
        res.status(500).json({ error: 'OTP verification failed' });
    }
});

// User login
app.post('/login', async (req, res) => {
    const { Email, Password } = req.body;

    if (!Email || !Password) {
        return res.status(400).json({ error: 'Email and Password are required' });
    }

    try {
        const user = await db.get('SELECT * FROM users WHERE Email = ?', [Email]);

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isPasswordMatch = await bcrypt.compare(Password, user.Password);
        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!user.verification) {
            const otp = crypto.randomInt(100000, 999999);
            const otpExpiry = Date.now() + 15 * 60 * 1000; // OTP expires in 15 minutes

            await db.run('UPDATE users SET otp = ?, otp_expiry = ?, verification = false WHERE id = ?', [otp, otpExpiry, user.id]);

            await transporter.sendMail({
                from: 'no-reply@gyan.com',
                to: Email,
                subject: 'Your OTP Code',
                text: `Your new OTP code is ${otp}`
            });

            return res.status(403).json({ error: 'Please verify your email before logging in. Check your email for a new OTP.', redirect: '/verify/signup' });
        }

        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ user: { id: user.id, fullName: user.fullName }, token });
    } catch (error) {
        console.error('Login failed', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Serve verification page
app.get('/verify/:userId', async (req, res) => {
    const userId = parseInt(req.params.userId, 10);

    try {
        res.sendFile(path.join(__dirname, 'public', 'verify.html'));
    } catch (error) {
        console.error('Failed to serve verification page', error);
        res.status(500).json({ error: 'Failed to serve verification page' });
    }
});

// Password reset
app.post('/reset/password', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ error: 'Email and new password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.run('UPDATE users SET Password = ? WHERE Email = ?', [hashedPassword, email]);
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Password reset failed', error);
        res.status(500).json({ error: 'Password reset failed' });
    }
});

// Serve dashboard page
app.get('/dashboard/:id', async (req, res) => {
    const userId = parseInt(req.params.id, 10);

    try {
        res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    } catch (error) {
        console.error('Failed to serve dashboard page', error);
        res.status(500).json({ error: 'Failed to serve dashboard page' });
    }
});

// Post a photo or media
app.post('/posts', authenticateToken, upload.single('media'), async (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id;
    const media = req.file;

    if (!title || !content || !media) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const mediaUrl = `/uploads/${media.filename}`;
    const mediaType = media.mimetype;

    try {
        const result = await db.run('INSERT INTO posts (userId, title, content, mediaUrl, mediaType, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?)', [
            userId,
            title,
            content,
            mediaUrl,
            mediaType,
            Date.now(),
            Date.now()
        ]);

        res.json({ message: 'Post created successfully', postId: result.lastID });
    } catch (error) {
        console.error('Failed to create post', error);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Like a post
app.post('/posts/:id/like', authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    const userId = req.user.id;

    try {
        const existingLike = await db.get('SELECT * FROM likes WHERE postId = ? AND userId = ?', [postId, userId]);

        if (existingLike) {
            return res.status(400).json({ error: 'You have already liked this post' });
        }

        await db.run('INSERT INTO likes (postId, userId) VALUES (?, ?)', [postId, userId]);
        res.json({ message: 'Post liked successfully' });
    } catch (error) {
        console.error('Failed to like post', error);
        res.status(500).json({ error: 'Failed to like post' });
    }
});

// Dislike a post
app.post('/posts/:id/dislike', authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    const userId = req.user.id;

    try {
        const existingDislike = await db.get('SELECT * FROM dislikes WHERE postId = ? AND userId = ?', [postId, userId]);

        if (existingDislike) {
            return res.status(400).json({ error: 'You have already disliked this post' });
        }

        await db.run('INSERT INTO dislikes (postId, userId) VALUES (?, ?)', [postId, userId]);
        res.json({ message: 'Post disliked successfully' });
    } catch (error) {
        console.error('Failed to dislike post', error);
        res.status(500).json({ error: 'Failed to dislike post' });
    }
});

// Add a comment to a post
app.post('/posts/:id/comment', authenticateToken, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    const userId = req.user.id;
    const { comment } = req.body;

    if (!comment) {
        return res.status(400).json({ error: 'Comment is required' });
    }

    try {
        await db.run('INSERT INTO comments (postId, userId, comment, createdAt) VALUES (?, ?, ?, ?)', [
            postId,
            userId,
            comment,
            Date.now()
        ]);

        res.json({ message: 'Comment added successfully' });
    } catch (error) {
        console.error('Failed to add comment', error);
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

// Get all posts with comments and likes
app.get('/posts', async (req, res) => {
    try {
        const posts = await db.all('SELECT posts.*, COUNT(likes.id) as likeCount, COUNT(dislikes.id) as dislikeCount FROM posts LEFT JOIN likes ON posts.id = likes.postId LEFT JOIN dislikes ON posts.id = dislikes.postId GROUP BY posts.id');

        // Fetch comments for each post
        for (let post of posts) {
            const comments = await db.all('SELECT * FROM comments WHERE postId = ?', [post.id]);
            post.comments = comments;
        }

        res.json(posts);
    } catch (error) {
        console.error('Failed to fetch posts', error);
        res.status(500).json({ error: 'Failed to fetch posts' });
    }
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
