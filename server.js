require('dotenv').config();

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
// Serve static files from the current directory
app.use(express.static(__dirname));

// Serve the login page at the root and the lowercase links used across the app.
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'Index.html'));
});
const sessionCookieName = 'cv_session';
const sessionDurationMs = 7 * 24 * 60 * 60 * 1000;
const allowedOrigins = (process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || (
    process.env.NODE_ENV === 'production'
        ? ''
        : 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:5501,http://127.0.0.1:5501'
)).split(',').map(origin => origin.trim()).filter(Boolean);

if (process.env.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    throw new Error('Set FRONTEND_ORIGINS to the trusted web app origin(s) in production.');
}

app.use(cors({
    credentials: true,
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Origin is not allowed by CORS'));
    }
}));
app.use(express.json({ limit: '1mb' }));

// 1. CONNECT TO THE LOCAL SQLITE DATABASE
// This creates the 'database.db' file automatically if it doesn't exist
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('✅ Connected to the SQLite database.');
});

// 2. CREATE THE USERS TABLE
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT
)`);
// Create the CVs table
db.run(`CREATE TABLE IF NOT EXISTS cvs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    cv_type TEXT, 
    name TEXT,
    email TEXT,
    phone TEXT,
    location TEXT,
    summary TEXT,
    education TEXT,
    skills TEXT,
    jobTitle TEXT,
    company TEXT,
    dates TEXT,
    jobDesc TEXT,
    advanced_data TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
)`);
db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
    session_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`);

function hashSessionId(sessionId) {
    return crypto.createHash('sha256').update(sessionId).digest('hex');
}

function setSessionCookie(res, sessionId) {
    const cookieParts = [
        `${sessionCookieName}=${encodeURIComponent(sessionId)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${Math.floor(sessionDurationMs / 1000)}`
    ];
    if (process.env.NODE_ENV === 'production') cookieParts.push('Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function clearSessionCookie(res) {
    const cookieParts = [
        `${sessionCookieName}=`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        'Max-Age=0'
    ];
    if (process.env.NODE_ENV === 'production') cookieParts.push('Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function createSession(userId, callback) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + sessionDurationMs;
    db.run(
        `INSERT INTO user_sessions (session_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)`,
        [hashSessionId(sessionId), userId, csrfToken, expiresAt],
        error => callback(error, error ? null : { sessionId, csrfToken, expiresAt })
    );
}

function replaceCurrentSession(req, userId, callback) {
    if (!req.authSession) return createSession(userId, callback);
    db.run(
        `DELETE FROM user_sessions WHERE session_hash = ?`,
        [req.authSession.session_hash],
        deleteError => {
            if (deleteError) return callback(deleteError);
            createSession(userId, callback);
        }
    );
}

function authenticate(req, res, next) {
    const cookieHeader = req.headers.cookie || '';
    const sessionCookie = cookieHeader.split(';')
        .map(part => part.trim())
        .find(part => part.startsWith(`${sessionCookieName}=`));
    if (!sessionCookie) {
        req.authSession = null;
        return next();
    }

    let sessionId;
    try {
        sessionId = decodeURIComponent(sessionCookie.slice(sessionCookieName.length + 1));
    } catch {
        clearSessionCookie(res);
        req.authSession = null;
        return next();
    }
    if (!/^[a-f0-9]{64}$/i.test(sessionId)) {
        clearSessionCookie(res);
        req.authSession = null;
        return next();
    }

    db.get(
        `SELECT session_hash, user_id, csrf_token, expires_at FROM user_sessions WHERE session_hash = ? AND expires_at > ?`,
        [hashSessionId(sessionId), Date.now()],
        (error, session) => {
            if (error) return res.status(500).json({ error: 'Could not verify session' });
            if (!session) {
                clearSessionCookie(res);
                req.authSession = null;
                return next();
            }
            req.authSession = session;
            next();
        }
    );
}

function requireAuthentication(req, res, next) {
    if (!req.authSession) return res.status(401).json({ error: 'Please log in to continue' });
    next();
}

function requireCsrfToken(req, res, next) {
    const token = req.get('X-CSRF-Token');
    if (!req.authSession || typeof token !== 'string' || !/^[a-f0-9]{64}$/i.test(token)
        || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.authSession.csrf_token))) {
        return res.status(403).json({ error: 'Invalid or missing CSRF token. Refresh the page and try again.' });
    }
    next();
}

function rotateUserSessions(userId, callback) {
    db.run(`DELETE FROM user_sessions WHERE user_id = ?`, [userId], deleteError => {
        if (deleteError) return callback(deleteError);
        createSession(userId, (createError, session) => {
            if (createError) return callback(createError);
            callback(null, session);
        });
    });
}

db.all(`PRAGMA table_info(cvs)`, (err, columns) => {
    if (err) {
        console.error('Could not inspect the CV database schema:', err.message);
        process.exitCode = 1;
        return;
    }

    const startServer = () => {
        const PORT = Number(process.env.PORT) || 3000;
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
        });
    };

    const createPasswordResetTable = () => {
        db.run(`CREATE TABLE IF NOT EXISTS password_resets (
            user_id INTEGER PRIMARY KEY,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`, (tableError) => {
            if (tableError) {
                console.error('Could not create password reset storage:', tableError.message);
                process.exitCode = 1;
                return;
            }
            db.run(`DELETE FROM user_sessions WHERE expires_at <= ?`, [Date.now()], cleanupError => {
                if (cleanupError) {
                    console.error('Could not remove expired sessions:', cleanupError.message);
                    process.exitCode = 1;
                    return;
                }
                startServer();
            });
        });
    };

    if (columns.some(column => column.name === 'advanced_data')) {
        createPasswordResetTable();
        return;
    }

    db.run(`ALTER TABLE cvs ADD COLUMN advanced_data TEXT`, (migrationError) => {
        if (migrationError) {
            if (migrationError.message.includes('duplicate column name: advanced_data')) {
                return db.all(`PRAGMA table_info(cvs)`, (verifyError, updatedColumns) => {
                    if (verifyError) {
                        console.error('Could not verify CV database migration:', verifyError.message);
                        process.exitCode = 1;
                        return;
                    }
                    if (updatedColumns.some(column => column.name === 'advanced_data')) {
                        return createPasswordResetTable();
                    }
                    console.error('Could not add advanced CV data storage:', migrationError.message);
                    process.exitCode = 1;
                });
            }
            console.error('Could not add advanced CV data storage:', migrationError.message);
            process.exitCode = 1;
            return;
        }
        createPasswordResetTable();
    });
});
app.use('/api', authenticate);

// 3. THE REGISTER API
app.post('/api/register', async (req, res) => {
    const { username, name, email, password } = req.body; // Added username

    if (!username || !name || !email || !password) {
        return res.status(400).json({ error: "Please fill all fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)`;
        
        db.run(sql, [username, name, email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed: users.email')) {
                    return res.status(400).json({ error: "Email already exists" });
                }
                if (err.message.includes('UNIQUE constraint failed: users.username')) {
                    return res.status(400).json({ error: "Username is already taken" });
                }
                return res.status(500).json({ error: "Database error" });
            }
            res.status(201).json({ message: "User created successfully!", userId: this.lastID });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error" });
    }
});
// 5. THE LOGIN API ENDPOINT
app.post('/api/login', (req, res) => {
    const { loginId, password } = req.body; // 'loginId' can be email OR username

    if (!loginId || !password) {
        return res.status(400).json({ error: "Please fill all fields" });
    }

    // The SQL now checks if the input matches the email OR the username
    const sql = `SELECT * FROM users WHERE email = ? OR username = ?`;
    
    db.get(sql, [loginId, loginId], async (err, user) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

        replaceCurrentSession(req, user.id, (sessionError, session) => {
            if (sessionError) {
                console.error('Could not create login session:', sessionError.message);
                return res.status(500).json({ error: 'Could not start a secure session' });
            }
            setSessionCookie(res, session.sessionId);
            res.status(200).json({
                message: "Login successful!",
                userName: user.name,
                username: user.username,
                email: user.email,
                csrfToken: session.csrfToken
            });
        });
    });
});

app.get('/api/session', (req, res) => {
    if (!req.authSession) return res.status(401).json({ error: 'Not logged in' });
    db.get(
        `SELECT id, username, name, email FROM users WHERE id = ?`,
        [req.authSession.user_id],
        (err, user) => {
        if (err) return res.status(500).json({ error: "Could not load account details" });
        if (!user) {
            clearSessionCookie(res);
            return res.status(401).json({ error: "Account not found" });
        }
        res.json({ ...user, csrfToken: req.authSession.csrf_token });
        }
    );
});

app.post('/api/logout', requireAuthentication, requireCsrfToken, (req, res) => {
    db.run(`DELETE FROM user_sessions WHERE session_hash = ?`, [req.authSession.session_hash], error => {
        if (error) return res.status(500).json({ error: 'Could not log out' });
        clearSessionCookie(res);
        res.json({ message: 'Logged out successfully' });
    });
});

app.get('/api/profile', requireAuthentication, (req, res) => {
    db.get(`SELECT id, username, name, email FROM users WHERE id = ?`, [req.authSession.user_id], (err, user) => {
        if (err) return res.status(500).json({ error: "Could not load account details" });
        if (!user) return res.status(404).json({ error: "Account not found" });
        res.json(user);
    });
});

app.put('/api/profile', requireAuthentication, requireCsrfToken, async (req, res) => {
    const { currentPassword, username, name, email, newPassword } = req.body;
    const parsedUserId = req.authSession.user_id;
    const normalizedUsername = typeof username === 'string' ? username.trim() : '';
    const normalizedName = typeof name === 'string' ? name.trim() : '';
    const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0 || !currentPassword) {
        return res.status(400).json({ error: "Current password and account details are required" });
    }
    if (!normalizedUsername || !normalizedName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
        return res.status(400).json({ error: "Enter a username, full name, and valid email address" });
    }
    if (newPassword && newPassword.length < 8) {
        return res.status(400).json({ error: "New password must be at least 8 characters" });
    }

    db.get(`SELECT id, password FROM users WHERE id = ?`, [parsedUserId], async (selectError, user) => {
        if (selectError) return res.status(500).json({ error: "Database error" });
        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: "Current password is incorrect" });
        }

        try {
            const passwordHash = newPassword ? await bcrypt.hash(newPassword, 10) : user.password;
            db.run(
                `UPDATE users SET username = ?, name = ?, email = ?, password = ? WHERE id = ?`,
                [normalizedUsername, normalizedName, normalizedEmail, passwordHash, parsedUserId],
                function(updateError) {
                    if (updateError) {
                        if (updateError.message.includes('UNIQUE constraint failed: users.email')) {
                            return res.status(409).json({ error: "Email is already in use" });
                        }
                        if (updateError.message.includes('UNIQUE constraint failed: users.username')) {
                            return res.status(409).json({ error: "Username is already taken" });
                        }
                        return res.status(500).json({ error: "Could not update account" });
                    }
                    db.run(`DELETE FROM password_resets WHERE user_id = ?`, [parsedUserId], (resetDeleteError) => {
                        if (resetDeleteError) {
                            console.error('Could not invalidate password reset links after profile update:', resetDeleteError.message);
                            return res.status(500).json({ error: "Account updated, but could not invalidate pending password resets" });
                        }
                        rotateUserSessions(parsedUserId, (sessionError, session) => {
                            if (sessionError) {
                                console.error('Could not rotate sessions after profile update:', sessionError.message);
                                return res.status(500).json({ error: "Account updated, but could not refresh the secure session" });
                            }
                            setSessionCookie(res, session.sessionId);
                            res.json({
                                message: "Account updated successfully",
                                username: normalizedUsername,
                                userName: normalizedName,
                                email: normalizedEmail,
                                csrfToken: session.csrfToken
                            });
                        });
                    });
                }
            );
        } catch (error) {
            console.error('Could not hash account password:', error);
            res.status(500).json({ error: "Could not update account" });
        }
    });
});

app.delete('/api/profile', requireAuthentication, requireCsrfToken, async (req, res) => {
    const parsedUserId = req.authSession.user_id;
    const currentPassword = req.body.currentPassword;
    if (typeof currentPassword !== 'string' || !currentPassword) {
        return res.status(400).json({ error: "Current password is required" });
    }

    db.get(`SELECT id, password FROM users WHERE id = ?`, [parsedUserId], async (selectError, user) => {
        if (selectError) return res.status(500).json({ error: "Could not delete account" });
        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: "Current password is incorrect" });
        }

        const rollback = (errorMessage, statusCode = 500) => {
            db.run('ROLLBACK', (rollbackError) => {
                if (rollbackError) console.error('Could not roll back account deletion:', rollbackError.message);
                res.status(statusCode).json({ error: errorMessage });
            });
        };

        db.run('BEGIN IMMEDIATE', (beginError) => {
            if (beginError) {
                console.error('Could not begin account deletion transaction:', beginError.message);
                return res.status(500).json({ error: "Could not delete account" });
            }

            db.run(`DELETE FROM cvs WHERE user_id = ?`, [parsedUserId], (cvError) => {
                if (cvError) return rollback("Could not delete saved CVs");

                db.run(`DELETE FROM password_resets WHERE user_id = ?`, [parsedUserId], (resetError) => {
                    if (resetError) return rollback("Could not remove account reset data");

                    db.run(`DELETE FROM user_sessions WHERE user_id = ?`, [parsedUserId], sessionError => {
                        if (sessionError) return rollback("Could not remove account sessions");

                        db.run(`DELETE FROM users WHERE id = ?`, [parsedUserId], function(userError) {
                            if (userError) return rollback("Could not delete account");
                            if (this.changes === 0) return rollback("Account not found", 404);

                            db.run('COMMIT', (commitError) => {
                                if (commitError) {
                                    console.error('Could not commit account deletion:', commitError.message);
                                    return rollback("Could not complete account deletion");
                                }
                                clearSessionCookie(res);
                                res.json({ message: "Account and saved CVs deleted successfully" });
                            });
                        });
                    });
                });
            });
        });
    });
});

app.post('/api/forgot-password', async (req, res) => {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: "Enter a valid email address" });
    }

    const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, APP_BASE_URL } = process.env;
    if (!SMTP_HOST || !SMTP_FROM || !APP_BASE_URL) {
        console.error('Password reset email is not configured. Set SMTP_HOST, SMTP_FROM, and APP_BASE_URL.');
        return res.status(503).json({ error: "Password reset email is not configured yet" });
    }
    if (Boolean(SMTP_USER) !== Boolean(SMTP_PASS)) {
        console.error('Password reset SMTP authentication requires both SMTP_USER and SMTP_PASS.');
        return res.status(503).json({ error: "Password reset email is not configured yet" });
    }
    let appBaseUrl;
    try {
        appBaseUrl = new URL(APP_BASE_URL);
        if (!['http:', 'https:'].includes(appBaseUrl.protocol)) throw new Error('Unsupported application URL protocol');
    } catch (configError) {
        console.error('APP_BASE_URL must be a valid HTTP or HTTPS URL:', configError.message);
        return res.status(503).json({ error: "Password reset email is not configured yet" });
    }

    db.get(`SELECT id, email FROM users WHERE LOWER(email) = ?`, [email], async (selectError, user) => {
        if (selectError) return res.status(500).json({ error: "Could not process password reset request" });
        if (!user) {
            return res.json({ message: "If an account exists for that email, a reset link will be sent." });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = Date.now() + 60 * 60 * 1000;
        db.run(
            `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET token_hash = excluded.token_hash, expires_at = excluded.expires_at`,
            [user.id, tokenHash, expiresAt],
            async (insertError) => {
                if (insertError) {
                    console.error('Could not create password reset token:', insertError.message);
                    return res.status(500).json({ error: "Could not process password reset request" });
                }

                try {
                    const port = Number(SMTP_PORT) || 587;
                    const transporter = nodemailer.createTransport({
                        host: SMTP_HOST,
                        port,
                        secure: process.env.SMTP_SECURE === 'true' || port === 465,
                        auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
                    });
                    const resetUrl = new URL('/reset-password.html', appBaseUrl);
                    resetUrl.searchParams.set('token', token);
                    await transporter.sendMail({
                        from: SMTP_FROM,
                        to: user.email,
                        subject: 'Reset your CV Generator password',
                        text: `Use this link to reset your password. It expires in one hour:\n\n${resetUrl.href}`,
                        html: `<p>Use the link below to reset your CV Generator password. It expires in one hour.</p><p><a href="${resetUrl.href}">Reset password</a></p>`
                    });
                    res.json({ message: "If an account exists for that email, a reset link will be sent." });
                } catch (mailError) {
                    console.error('Could not send password reset email:', mailError);
                    db.run(`DELETE FROM password_resets WHERE user_id = ? AND token_hash = ?`, [user.id, tokenHash], (deleteError) => {
                        if (deleteError) console.error('Could not remove unsent reset token:', deleteError.message);
                        res.status(503).json({ error: "Could not send the reset email. Check the email server settings and try again." });
                    });
                }
            }
        );
    });
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]+$/i.test(token)) {
        return res.status(400).json({ error: "This password reset link is invalid or expired" });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    db.get(
        `SELECT user_id FROM password_resets WHERE token_hash = ? AND expires_at > ?`,
        [tokenHash, Date.now()],
        async (selectError, reset) => {
            if (selectError) return res.status(500).json({ error: "Could not reset password" });
            if (!reset) return res.status(400).json({ error: "This password reset link is invalid or expired" });

            try {
                const passwordHash = await bcrypt.hash(newPassword, 10);
                db.run(`UPDATE users SET password = ? WHERE id = ?`, [passwordHash, reset.user_id], function(updateError) {
                    if (updateError) return res.status(500).json({ error: "Could not reset password" });
                    db.run(`DELETE FROM user_sessions WHERE user_id = ?`, [reset.user_id], sessionError => {
                        if (sessionError) {
                            console.error('Could not revoke sessions after password reset:', sessionError.message);
                            return res.status(500).json({ error: "Password changed, but existing sessions could not be revoked" });
                        }
                        db.run(`DELETE FROM password_resets WHERE user_id = ?`, [reset.user_id], (deleteError) => {
                            if (deleteError) return res.status(500).json({ error: "Password changed, but the reset link could not be invalidated" });
                            res.json({ message: "Password reset successfully. You can now sign in." });
                        });
                    });
                });
            } catch (hashError) {
                console.error('Could not hash reset password:', hashError);
                res.status(500).json({ error: "Could not reset password" });
            }
        }
    );
});
// 6. SAVED CV API ENDPOINTS
app.post('/api/save-cv', requireAuthentication, requireCsrfToken, (req, res) => {
    const { 
        cvId, cvType, name, email, phone, location, summary, 
        education, skills, jobTitle, company, dates, jobDesc, advancedData
    } = req.body;

    const parsedUserId = req.authSession.user_id;

    if (advancedData !== undefined && (advancedData === null || typeof advancedData !== 'object' || Array.isArray(advancedData))) {
        return res.status(400).json({ error: "Advanced CV data must be an object" });
    }

    const normalizedAdvancedData = advancedData || {
        educationList: [],
        experienceList: [],
        projects: [],
        portfolioLinks: []
    };
    const advancedDataJson = JSON.stringify(normalizedAdvancedData);
    const values = [cvType, name, email, phone, location, summary, education, skills, jobTitle, company, dates, jobDesc, advancedDataJson];
    if (cvId !== undefined && cvId !== null && cvId !== '') {
        const parsedCvId = Number(cvId);
        if (!Number.isInteger(parsedCvId) || parsedCvId <= 0) {
            return res.status(400).json({ error: "Invalid CV ID" });
        }

        const updateSql = `UPDATE cvs SET cv_type=?, name=?, email=?, phone=?, location=?, summary=?, education=?, skills=?, jobTitle=?, company=?, dates=?, jobDesc=?, advanced_data=?, last_updated=CURRENT_TIMESTAMP WHERE id=? AND user_id=?`;
        return db.run(updateSql, [...values, parsedCvId, parsedUserId], function(err) {
            if (err) return res.status(500).json({ error: "Error updating CV" });
            if (this.changes === 0) return res.status(404).json({ error: "CV not found" });
            res.status(200).json({ message: "CV updated successfully!", cvId: parsedCvId });
        });
    }

    const insertSql = `INSERT INTO cvs (user_id, cv_type, name, email, phone, location, summary, education, skills, jobTitle, company, dates, jobDesc, advanced_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(insertSql, [parsedUserId, ...values], function(err) {
        if (err) return res.status(500).json({ error: "Error saving CV" });
        res.status(201).json({ message: "CV saved successfully!", cvId: this.lastID });
    });
});

app.get('/api/cvs', requireAuthentication, (req, res) => {
    db.all(
        `SELECT id, cv_type, name, last_updated FROM cvs WHERE user_id = ? ORDER BY last_updated DESC, id DESC`,
        [req.authSession.user_id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: "Database error" });
            res.json(rows);
        }
    );
});

app.get('/api/cvs/:id', requireAuthentication, (req, res) => {
    const cvId = Number(req.params.id);
    if (!Number.isInteger(cvId) || cvId <= 0) {
        return res.status(400).json({ error: "Valid CV ID is required" });
    }

    db.get(`SELECT * FROM cvs WHERE id = ? AND user_id = ?`, [cvId, req.authSession.user_id], (err, row) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!row) return res.status(404).json({ error: "CV not found" });
        try {
            row.advancedData = row.advanced_data ? JSON.parse(row.advanced_data) : {
                educationList: [],
                experienceList: [],
                projects: [],
                portfolioLinks: []
            };
            delete row.advanced_data;
        } catch (parseError) {
            console.error('Could not parse saved advanced CV data:', parseError);
            return res.status(500).json({ error: "Saved CV data is invalid" });
        }
        res.json(row);
    });
});

app.delete('/api/cvs/:id', requireAuthentication, requireCsrfToken, (req, res) => {
    const cvId = Number(req.params.id);
    if (!Number.isInteger(cvId) || cvId <= 0) {
        return res.status(400).json({ error: "Valid CV ID is required" });
    }

    db.run(`DELETE FROM cvs WHERE id = ? AND user_id = ?`, [cvId, req.authSession.user_id], function(err) {
        if (err) return res.status(500).json({ error: "Database error" });
        if (this.changes === 0) return res.status(404).json({ error: "CV not found" });
        res.json({ message: "CV deleted successfully" });
    });
});