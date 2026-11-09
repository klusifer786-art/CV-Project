const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const sqlite3 = require('sqlite3').verbose();

const serverFile = path.resolve(__dirname, '..', 'server.js');
let serverProcess;
let serverUrl;
let databaseDirectory;

async function getAvailablePort() {
    const listener = net.createServer();
    listener.listen(0, '127.0.0.1');
    await once(listener, 'listening');
    const { port } = listener.address();
    await new Promise((resolve, reject) => {
        listener.close(error => error ? reject(error) : resolve());
    });
    return port;
}

async function runTestDatabase(sql, values) {
    const database = new sqlite3.Database(path.join(databaseDirectory, 'database.db'));
    await new Promise((resolve, reject) => {
        database.run(sql, values, error => error ? reject(error) : resolve());
    });
    await new Promise((resolve, reject) => {
        database.close(error => error ? reject(error) : resolve());
    });
}

function createApiClient() {
    let cookie = '';
    let cookieAttributes = '';
    let csrfToken = '';
    return {
        get csrfToken() {
            return csrfToken;
        },
        get cookieAttributes() {
            return cookieAttributes;
        },
        async request(method, route, body, { includeCsrf = true, csrfTokenOverride } = {}) {
            const headers = {
                Origin: 'http://localhost:5500',
                'Content-Type': 'application/json'
            };
            if (cookie) headers.Cookie = cookie;
            const requestCsrfToken = csrfTokenOverride || csrfToken;
            if (includeCsrf && requestCsrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
                headers['X-CSRF-Token'] = requestCsrfToken;
            }
            const response = await fetch(`${serverUrl}${route}`, {
                method,
                headers,
                ...(body === undefined ? {} : { body: JSON.stringify(body) })
            });
            const setCookies = response.headers.getSetCookie();
            if (setCookies.length) {
                cookieAttributes = setCookies[0];
                cookie = cookieAttributes.split(';', 1)[0];
            }
            const responseBody = await response.json();
            if (responseBody.csrfToken) csrfToken = responseBody.csrfToken;
            return { status: response.status, body: responseBody };
        }
    };
}

before(async () => {
    const port = await getAvailablePort();
    serverUrl = `http://127.0.0.1:${port}`;
    databaseDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-project-api-test-'));

    serverProcess = spawn(process.execPath, [serverFile], {
        cwd: databaseDirectory,
        env: {
            ...process.env,
            PORT: String(port),
            FRONTEND_ORIGINS: 'http://localhost:5500',
            SMTP_HOST: '',
            SMTP_PORT: '',
            SMTP_USER: '',
            SMTP_PASS: '',
            SMTP_FROM: '',
            APP_BASE_URL: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    await new Promise((resolve, reject) => {
        let output = '';
        const timeout = setTimeout(() => reject(new Error(`Server did not start. Output: ${output}`)), 15000);
        const onData = chunk => {
            output += chunk.toString();
            if (output.includes(`Server running on http://localhost:${port}`)) {
                clearTimeout(timeout);
                resolve();
            }
        };
        serverProcess.stdout.on('data', onData);
        serverProcess.stderr.on('data', onData);
        serverProcess.once('error', error => {
            clearTimeout(timeout);
            reject(error);
        });
        serverProcess.once('exit', code => {
            clearTimeout(timeout);
            reject(new Error(`Server exited before starting (code ${code}). Output: ${output}`));
        });
    });
});

after(async () => {
    if (serverProcess && serverProcess.exitCode === null) {
        const exited = once(serverProcess, 'exit');
        serverProcess.kill();
        await exited;
    }
    if (databaseDirectory) fs.rmSync(databaseDirectory, { recursive: true, force: true });
});

test('server sessions protect accounts and saved CVs end to end', async t => {
    const client = createApiClient();
    const otherClient = createApiClient();
    const anonymousClient = createApiClient();

    const registration = await client.request('POST', '/api/register', {
        username: 'test-user',
        name: 'Test User',
        email: 'test@example.com',
        password: 'TestPassword123'
    });
    assert.equal(registration.status, 201);
    const userId = registration.body.userId;
    assert.ok(userId);

    const deniedProfile = await anonymousClient.request('GET', `/api/profile?userId=${userId}`);
    assert.equal(deniedProfile.status, 401);
    const spoofedSave = await anonymousClient.request('POST', '/api/save-cv', { userId });
    assert.equal(spoofedSave.status, 401);

    const duplicateRegistration = await client.request('POST', '/api/register', {
        username: 'another-user',
        name: 'Another User',
        email: 'test@example.com',
        password: 'TestPassword123'
    });
    assert.equal(duplicateRegistration.status, 400);

    const invalidLogin = await client.request('POST', '/api/login', {
        loginId: 'test-user',
        password: 'incorrect'
    });
    assert.equal(invalidLogin.status, 400);

    const login = await client.request('POST', '/api/login', {
        loginId: 'test-user',
        password: 'TestPassword123'
    });
    assert.equal(login.status, 200);
    assert.equal(typeof login.body.csrfToken, 'string');
    assert.equal(login.body.userId, undefined);
    assert.match(login.body.csrfToken, /^[a-f0-9]{64}$/);
    assert.match(client.cookieAttributes, /HttpOnly/i);
    assert.match(client.cookieAttributes, /SameSite=Lax/i);
    assert.match(client.cookieAttributes, /Max-Age=604800/i);

    const session = await client.request('GET', '/api/session');
    assert.equal(session.status, 200);
    assert.equal(session.body.email, 'test@example.com');

    const profile = await client.request('GET', `/api/profile?userId=999999`);
    assert.equal(profile.status, 200);
    assert.equal(profile.body.email, 'test@example.com');

    const noCsrfUpdate = await client.request('PUT', '/api/profile', {
        currentPassword: 'TestPassword123',
        username: 'test-user',
        name: 'Test User',
        email: 'test@example.com'
    }, { includeCsrf: false });
    assert.equal(noCsrfUpdate.status, 403);

    const wrongPasswordUpdate = await client.request('PUT', '/api/profile', {
        userId: 999999,
        currentPassword: 'incorrect',
        username: 'test-user',
        name: 'Test User',
        email: 'test@example.com'
    });
    assert.equal(wrongPasswordUpdate.status, 401);

    const profileUpdate = await client.request('PUT', '/api/profile', {
        userId: 999999,
        currentPassword: 'TestPassword123',
        username: 'test-user-updated',
        name: 'Updated User',
        email: 'updated@example.com',
        newPassword: 'UpdatedPassword123'
    });
    assert.equal(profileUpdate.status, 200);
    assert.equal(profileUpdate.body.email, 'updated@example.com');

    const rotatedSession = await client.request('GET', '/api/session');
    assert.equal(rotatedSession.status, 200);
    assert.equal(rotatedSession.body.csrfToken, profileUpdate.body.csrfToken);

    const cvData = {
        userId: 999999,
        cvType: 'experienced',
        name: 'Updated User',
        email: 'updated@example.com',
        skills: 'Java, Python',
        advancedData: {
            experienceList: [{ title: 'Engineer', company: 'Example Co' }],
            educationList: [{ degree: 'Diploma', school: 'Example Institute' }],
            projects: [],
            portfolioLinks: [],
            profilePhotoData: 'data:image/jpeg;base64,dGVzdA==',
            profilePhotoCrop: { zoom: 1.5, x: 65, y: 40 }
        }
    };
    const savedCv = await client.request('POST', '/api/save-cv', cvData);
    assert.equal(savedCv.status, 201);
    const cvId = savedCv.body.cvId;

    const cvList = await client.request('GET', `/api/cvs?userId=999999`);
    assert.equal(cvList.status, 200);
    assert.equal(cvList.body.length, 1);
    assert.equal(cvList.body[0].id, cvId);

    const loadedCv = await client.request('GET', `/api/cvs/${cvId}?userId=999999`);
    assert.equal(loadedCv.status, 200);
    assert.deepEqual(loadedCv.body.advancedData.profilePhotoCrop, { zoom: 1.5, x: 65, y: 40 });
    assert.equal(loadedCv.body.advancedData.profilePhotoData, cvData.advancedData.profilePhotoData);

    const updatedCv = await client.request('POST', '/api/save-cv', {
        ...cvData,
        cvId,
        skills: 'JavaScript'
    });
    assert.equal(updatedCv.status, 200);
    const reloadedCv = await client.request('GET', `/api/cvs/${cvId}?userId=999999`);
    assert.equal(reloadedCv.body.skills, 'JavaScript');

    const secondRegistration = await otherClient.request('POST', '/api/register', {
        username: 'other-user',
        name: 'Other User',
        email: 'other@example.com',
        password: 'OtherPassword123'
    });
    assert.equal(secondRegistration.status, 201);
    const otherUserId = secondRegistration.body.userId;
    await otherClient.request('POST', '/api/login', {
        loginId: 'other-user',
        password: 'OtherPassword123'
    });
    const otherAccountWithWrongCsrf = await otherClient.request('POST', '/api/save-cv', {
        name: 'Must not save'
    }, { csrfTokenOverride: client.csrfToken });
    assert.equal(otherAccountWithWrongCsrf.status, 403);

    const crossAccountRead = await otherClient.request('GET', `/api/cvs/${cvId}?userId=${userId}`);
    assert.equal(crossAccountRead.status, 404);
    const crossAccountDelete = await otherClient.request('DELETE', `/api/cvs/${cvId}`, { userId });
    assert.equal(crossAccountDelete.status, 404);

    const deletedCv = await client.request('DELETE', `/api/cvs/${cvId}`, { userId: otherUserId });
    assert.equal(deletedCv.status, 200);
    assert.equal((await client.request('GET', `/api/cvs/${cvId}`)).status, 404);

    const savedSecondCv = await client.request('POST', '/api/save-cv', cvData);
    assert.equal(savedSecondCv.status, 201);

    const rejectedDeletion = await client.request('DELETE', '/api/profile', {
        userId: otherUserId,
        currentPassword: 'incorrect'
    });
    assert.equal(rejectedDeletion.status, 401);

    const deletedAccount = await client.request('DELETE', '/api/profile', {
        userId: otherUserId,
        currentPassword: 'UpdatedPassword123'
    });
    assert.equal(deletedAccount.status, 200);
    assert.equal((await client.request('GET', '/api/session')).status, 401);
    assert.equal(deletedAccount.body.message, 'Account and saved CVs deleted successfully');

    const otherProfile = await otherClient.request('GET', `/api/profile?userId=${otherUserId}`);
    assert.equal(otherProfile.status, 200);

    await t.test('password reset revokes active server sessions', async () => {
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        await runTestDatabase(
            `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
            [otherUserId, tokenHash, Date.now() + 60 * 60 * 1000]
        );
        const reset = await otherClient.request('POST', '/api/reset-password', {
            token: resetToken,
            newPassword: 'ResetPassword123'
        });
        assert.equal(reset.status, 200);
        assert.equal((await otherClient.request('GET', '/api/session')).status, 401);
        const relogin = await otherClient.request('POST', '/api/login', {
            loginId: 'other-user',
            password: 'ResetPassword123'
        });
        assert.equal(relogin.status, 200);
    });

    await t.test('protected routes reject expired or absent sessions and missing CSRF tokens', async () => {
        const noCsrf = await otherClient.request('DELETE', '/api/profile', {
            currentPassword: 'ResetPassword123'
        }, { includeCsrf: false });
        assert.equal(noCsrf.status, 403);

        const logout = await otherClient.request('POST', '/api/logout');
        assert.equal(logout.status, 200);
        assert.equal((await otherClient.request('GET', '/api/cvs')).status, 401);
    });
});
