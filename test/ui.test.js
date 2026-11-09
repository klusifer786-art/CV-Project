const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { after, before, test } = require('node:test');
const { chromium } = require('playwright');

const projectDirectory = path.resolve(__dirname, '..');
const apiBaseUrl = 'http://127.0.0.1:3000';
const testCorsHeaders = origin => ({
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true'
});
let browser;
let staticServer;
let baseUrl;

function serveProjectFile(request, response) {
    const requestPath = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const relativePath = requestPath === '/' ? 'dashboard.html' : requestPath.slice(1);
    const filePath = path.resolve(projectDirectory, relativePath);
    if (!filePath.startsWith(`${projectDirectory}${path.sep}`)) {
        response.writeHead(403).end();
        return;
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            response.writeHead(404).end();
            return;
        }
        const contentType = filePath.endsWith('.css') ? 'text/css' : 'text/html';
        response.writeHead(200, { 'Content-Type': `${contentType}; charset=utf-8` });
        response.end(content);
    });
}

async function openEditor({ registered = false, acceptDownloads = false } = {}) {
    const context = await browser.newContext({ acceptDownloads });
    await context.route('https://cdnjs.cloudflare.com/**', route => route.abort());
    if (registered) {
        await context.route(`${apiBaseUrl}/api/session`, route => route.fulfill({
            status: 200,
            headers: testCorsHeaders(route.request().headers().origin),
            contentType: 'application/json',
            body: JSON.stringify({
                id: 1,
                username: 'test-user',
                name: 'Test User',
                email: 'test@example.com',
                csrfToken: 'a'.repeat(64)
            })
        }));
    }
    const page = await context.newPage();
    const mode = registered ? '' : '&mode=guest';
    await page.goto(`${baseUrl}/dashboard.html?type=experienced${mode}`);
    return { context, page };
}

async function setSlider(page, selector, value) {
    await page.locator(selector).evaluate((element, nextValue) => {
        element.value = String(nextValue);
        element.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
}

async function uploadGeneratedPhoto(page) {
    const dataUrl = await page.evaluate(async () => {
        const canvas = document.createElement('canvas');
        canvas.width = 400;
        canvas.height = 300;
        const context = canvas.getContext('2d');
        context.fillStyle = '#d55';
        context.fillRect(0, 0, 200, 300);
        context.fillStyle = '#55d';
        context.fillRect(200, 0, 200, 300);
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
        });
    });
    await page.locator('#input-photo').setInputFiles({
        name: 'test-portrait.png',
        mimeType: 'image/png',
        buffer: Buffer.from(dataUrl.split(',')[1], 'base64')
    });
    await page.waitForFunction(() => document.querySelector('#photo-crop-preview').naturalWidth > 0);
}

before(async () => {
    browser = await chromium.launch({ headless: true });
    staticServer = http.createServer(serveProjectFile);
    staticServer.listen(0, '127.0.0.1');
    await once(staticServer, 'listening');
    baseUrl = `http://127.0.0.1:${staticServer.address().port}`;
});

after(async () => {
    if (browser) await browser.close();
    if (staticServer) {
        await new Promise((resolve, reject) => {
            staticServer.close(error => error ? reject(error) : resolve());
        });
    }
});

test('successful login reaches the home page when local storage is unavailable', async () => {
    const context = await browser.newContext();
    await context.route(`${apiBaseUrl}/api/**`, async route => {
        const request = route.request();
        const url = new URL(request.url());
        const headers = testCorsHeaders(request.headers().origin);

        if (request.method() === 'OPTIONS') {
            await route.fulfill({
                status: 204,
                headers: {
                    ...headers,
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'content-type'
                }
            });
        } else if (request.method() === 'POST' && url.pathname === '/api/login') {
            await route.fulfill({
                status: 200,
                headers,
                contentType: 'application/json',
                body: JSON.stringify({
                    userName: 'Test User',
                    username: 'test-user',
                    email: 'test@example.com',
                    csrfToken: 'a'.repeat(64)
                })
            });
        } else if (request.method() === 'GET' && url.pathname === '/api/session') {
            await route.fulfill({
                status: 200,
                headers,
                contentType: 'application/json',
                body: JSON.stringify({
                    name: 'Test User',
                    username: 'test-user',
                    email: 'test@example.com',
                    csrfToken: 'a'.repeat(64)
                })
            });
        } else if (request.method() === 'GET' && url.pathname === '/api/cvs') {
            await route.fulfill({ status: 200, headers, contentType: 'application/json', body: '[]' });
        } else {
            await route.fulfill({ status: 404, headers, contentType: 'application/json', body: '{}' });
        }
    });

    await context.addInitScript(() => {
        Storage.prototype.setItem = () => { throw new DOMException('Storage is unavailable', 'QuotaExceededError'); };
        Storage.prototype.removeItem = () => { throw new DOMException('Storage is unavailable', 'QuotaExceededError'); };
    });

    const page = await context.newPage();
    try {
        await page.goto(`${baseUrl}/Index.html`);
        await page.locator('#email').fill('test-user');
        await page.locator('#password').fill('TestPassword123');
        await page.locator('button[type="submit"]').click();

        await page.waitForURL('**/home.html');
        await page.waitForFunction(() => document.getElementById('welcome-message').textContent === 'Welcome back, Test User!');
        assert.match(page.url(), /\/home\.html$/);
    } finally {
        await context.close();
    }
});

test('guest editing, photo cropping, and local draft persistence work in the browser', async () => {
    const { context, page } = await openEditor();
    try {
        await page.locator('#input-name').fill('Guest Test User');
        await page.locator('#tab-skills').click();
        await page.locator('#input-skills').fill('Java, Testing');
        assert.equal(await page.locator('#preview-name').textContent(), 'Guest Test User');
        assert.deepEqual(await page.locator('#preview-skills li').allTextContents(), ['Java', 'Testing']);

        await page.locator('#tab-personal').click();
        await uploadGeneratedPhoto(page);
        await setSlider(page, '#photo-zoom', 1.8);
        await setSlider(page, '#photo-horizontal', 70);
        await setSlider(page, '#photo-vertical', 35);

        const cropBeforeDrag = await page.evaluate(() => {
            const cropPosition = (frameId, imageId) => {
                const frame = document.getElementById(frameId);
                const image = document.getElementById(imageId);
                const overflowX = Math.max(0, parseFloat(image.style.width) - frame.clientWidth);
                const overflowY = Math.max(0, parseFloat(image.style.height) - frame.clientHeight);
                return {
                    x: overflowX ? -parseFloat(image.style.left) / overflowX : 0,
                    y: overflowY ? -parseFloat(image.style.top) / overflowY : 0
                };
            };
            return {
                zoom: Number(document.querySelector('#photo-zoom').value),
                x: Number(document.querySelector('#photo-horizontal').value),
                y: Number(document.querySelector('#photo-vertical').value),
                previewCrop: cropPosition('preview-photo-frame', 'preview-photo'),
                cropPreview: cropPosition('photo-crop-frame', 'photo-crop-preview')
            };
        });
        assert.equal(cropBeforeDrag.zoom, 1.8);
        assert.equal(cropBeforeDrag.x, 70);
        assert.equal(cropBeforeDrag.y, 35);
        for (const crop of [cropBeforeDrag.previewCrop, cropBeforeDrag.cropPreview]) {
            assert.ok(Math.abs(crop.x - 0.7) < 0.01);
            assert.ok(Math.abs(crop.y - 0.35) < 0.01);
        }

        const cropFrame = await page.locator('#photo-crop-frame').boundingBox();
        await page.mouse.move(cropFrame.x + cropFrame.width / 2, cropFrame.y + cropFrame.height / 2);
        await page.mouse.down();
        await page.mouse.move(cropFrame.x + cropFrame.width / 2 + 20, cropFrame.y + cropFrame.height / 2 - 15);
        await page.mouse.up();
        const positionAfterDrag = await page.evaluate(() => ({
            x: Number(document.querySelector('#photo-horizontal').value),
            y: Number(document.querySelector('#photo-vertical').value)
        }));
        assert.notEqual(positionAfterDrag.x, cropBeforeDrag.x);
        assert.notEqual(positionAfterDrag.y, cropBeforeDrag.y);

        await page.locator('#reset-photo-crop-btn').click();
        assert.deepEqual(await page.evaluate(() => ({
            zoom: Number(document.querySelector('#photo-zoom').value),
            x: Number(document.querySelector('#photo-horizontal').value),
            y: Number(document.querySelector('#photo-vertical').value)
        })), { zoom: 1, x: 50, y: 50 });

        await setSlider(page, '#photo-zoom', 1.5);
        await setSlider(page, '#photo-horizontal', 80);
        await setSlider(page, '#photo-vertical', 25);
        await page.reload();

        assert.equal(await page.locator('#input-name').inputValue(), 'Guest Test User');
        assert.equal(await page.locator('#preview-photo-frame').isVisible(), true);
        assert.deepEqual(await page.evaluate(() => ({
            zoom: Number(document.querySelector('#photo-zoom').value),
            x: Number(document.querySelector('#photo-horizontal').value),
            y: Number(document.querySelector('#photo-vertical').value),
            stored: JSON.parse(localStorage.getItem('guestCVData')).profilePhotoCrop
        })), {
            zoom: 1.5,
            x: 80,
            y: 25,
            stored: { zoom: 1.5, x: 80, y: 25 }
        });
    } finally {
        await context.close();
    }
});

test('registered CVs save and reload through the editor with photo crop settings', async () => {
    const { context, page } = await openEditor({ registered: true });
    let savedCv;
    await context.route(`${apiBaseUrl}/api/**`, async route => {
        const request = route.request();
        const url = new URL(request.url());
        if (request.method() === 'GET' && url.pathname === '/api/session') {
            await route.fulfill({
                status: 200,
                headers: testCorsHeaders(request.headers().origin),
                contentType: 'application/json',
                body: JSON.stringify({
                    id: 1,
                    username: 'test-user',
                    name: 'Test User',
                    email: 'test@example.com',
                    csrfToken: 'a'.repeat(64)
                })
            });
        } else if (request.method() === 'OPTIONS') {
            await route.fulfill({
                status: 204,
                headers: {
                    ...testCorsHeaders(request.headers().origin),
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'content-type'
                }
            });
        } else if (request.method() === 'POST' && url.pathname === '/api/save-cv') {
            savedCv = request.postDataJSON();
            await route.fulfill({
                status: 201,
                headers: testCorsHeaders(request.headers().origin),
                contentType: 'application/json',
                body: JSON.stringify({ cvId: 42, message: 'CV saved successfully!' })
            });
        } else if (request.method() === 'GET' && url.pathname === '/api/cvs/42') {
            await route.fulfill({
                status: 200,
                headers: testCorsHeaders(request.headers().origin),
                contentType: 'application/json',
                body: JSON.stringify({
                    ...savedCv,
                    id: 42,
                    advancedData: savedCv.advancedData
                })
            });
        } else {
            await route.fulfill({
                status: 404,
                headers: testCorsHeaders(request.headers().origin),
                contentType: 'application/json',
                body: JSON.stringify({ error: 'Unexpected test API request' })
            });
        }
    });

    page.on('dialog', dialog => dialog.accept());
    try {
        await page.locator('#save-btn').waitFor({ state: 'visible' });
        await page.locator('#input-name').fill('Registered Test User');
        await page.locator('#tab-education').click();
        await page.locator('#input-education').fill('Diploma');
        await page.locator('#input-education-school').fill('Test Institute');
        await page.locator('#tab-skills').click();
        await page.locator('#input-skills').fill('Java, Testing');
        await page.locator('#tab-personal').click();
        await uploadGeneratedPhoto(page);
        await setSlider(page, '#photo-zoom', 1.7);
        await setSlider(page, '#photo-horizontal', 72);
        await setSlider(page, '#photo-vertical', 31);

        await page.locator('#save-btn').click();
        await page.waitForFunction(() => new URL(location.href).searchParams.get('cvId') === '42');
        assert.equal(savedCv.name, 'Registered Test User');
        assert.equal(savedCv.advancedData.educationList[0].school, 'Test Institute');
        assert.equal(savedCv.advancedData.profilePhotoCrop.zoom, 1.7);
        assert.equal(savedCv.advancedData.profilePhotoCrop.x, 72);
        assert.equal(savedCv.advancedData.profilePhotoCrop.y, 31);
        assert.match(savedCv.profilePhotoData, /^data:image\/jpeg;base64,/);

        await page.reload();
        await page.waitForFunction(() => document.querySelector('#input-name').value === 'Registered Test User');
        assert.equal(await page.locator('#input-education-school').inputValue(), 'Test Institute');
        assert.deepEqual(await page.evaluate(() => ({
            zoom: Number(document.querySelector('#photo-zoom').value),
            x: Number(document.querySelector('#photo-horizontal').value),
            y: Number(document.querySelector('#photo-vertical').value)
        })), { zoom: 1.7, x: 72, y: 31 });
        assert.equal(await page.locator('#preview-photo-frame').isVisible(), true);
    } finally {
        await context.close();
    }
});

test('the PDF action downloads a PDF blob from the renderer', async () => {
    const { context, page } = await openEditor({ acceptDownloads: true });
    try {
        await page.evaluate(() => {
            window.html2pdf = () => ({
                set() { return this; },
                from() { return this; },
                async outputPdf() {
                    return new Blob(['%PDF-1.4\nbrowser-test\n%%EOF'], { type: 'application/pdf' });
                }
            });
        });

        const downloadPromise = page.waitForEvent('download');
        await page.locator('#download-btn').click();
        const download = await downloadPromise;
        assert.equal(download.suggestedFilename(), 'My_CV.pdf');
        const downloadedFile = await download.path();
        assert.ok(downloadedFile);
        assert.match(fs.readFileSync(downloadedFile, 'utf8'), /^%PDF-1\.4/);
    } finally {
        await context.close();
    }
});
