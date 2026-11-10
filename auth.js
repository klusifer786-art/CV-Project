(() => {
    const configuredApiUrl = new URL(
        document.querySelector('meta[name="api-base-url"]')?.content || 'http://localhost:3000',
        window.location.href
    );
    const loopbackHosts = new Set(['localhost', '127.0.0.1']);
    if (loopbackHosts.has(window.location.hostname) && loopbackHosts.has(configuredApiUrl.hostname)) {
        configuredApiUrl.hostname = window.location.hostname;
    } else if (!loopbackHosts.has(window.location.hostname) && loopbackHosts.has(configuredApiUrl.hostname)) {
        configuredApiUrl.href = window.location.origin;
    }
    const apiBaseUrl = configuredApiUrl.href.replace(/\/+$/, '');
    const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
    let csrfToken = '';

    window.apiRequest = async (path, options = {}) => {
        const method = (options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        if (unsafeMethods.has(method) && csrfToken) headers.set('X-CSRF-Token', csrfToken);

        const response = await fetch(`${apiBaseUrl}${path}`, {
            ...options,
            method,
            headers,
            credentials: 'include'
        });
        if ((response.headers.get('content-type') || '').includes('application/json')) {
            const result = await response.clone().json();
            if (typeof result.csrfToken === 'string') csrfToken = result.csrfToken;
        }
        return response;
    };

    window.clearApiSessionState = () => {
        csrfToken = '';
    };
})();
