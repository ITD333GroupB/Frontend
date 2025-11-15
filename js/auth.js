        // --- Login Bar Logic (from navbar_login.html) ---
        function parseJwt(token) {
            try {
                const base64Url = token.split('.')[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
                return JSON.parse(jsonPayload);
            } catch (e) {
                return null;
            }
        }
        function getUsernameFromToken(token) {
            const payload = parseJwt(token);
            return payload ? payload.username : null;
        }
        function isLoggedIn() {
            const authToken = document.cookie.split('; ').find(row => row.startsWith('authToken='));
            const token = authToken ? authToken.split('=')[1] : null;

            if (!token) {
                return null;
            }

            // Check if token is expired
            const payload = parseJwt(token);
            if (!payload || !payload.exp) {
                return null;
            }

            const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
            if (payload.exp < currentTime) {
                // Token is expired, remove it
                var isHttps = (typeof location !== 'undefined') && location.protocol === 'https:';
                document.cookie = 'authToken=; max-age=0; path=/; SameSite=Lax' + (isHttps ? '; secure' : '');
                return null;
            }

            return token;
        }
        function logout() {
            var isHttps = (typeof location !== 'undefined') && location.protocol === 'https:';
            document.cookie = 'authToken=; max-age=0; path=/; SameSite=Lax' + (isHttps ? '; secure' : '');
            localStorage.removeItem('jwtToken');
            localStorage.removeItem('refreshToken');
            localStorage.removeItem('loginData');
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            try {
                const response = await fetch(`${BASE_URL}api/auth/login`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                if (response.ok) {
                    const data = await response.json();
                    let jwt = null;
                    let refreshToken = null;

                    const loginData = {
                        username: username,
                        success: data.success,
                        messages: data.messages || {},
                        loginTime: new Date().toISOString()
                    };
                    localStorage.setItem('loginData', JSON.stringify(loginData));

                    // Parse data.token (server returns serialized ApiToken JSON string) and extract JWT + refresh
                    try {
                        let raw = data.token; // may be stringified JSON or already an object/string
                        let parsed = raw;
                        if (typeof parsed === 'string') {
                            try { parsed = JSON.parse(parsed); } catch { /* not JSON, treat as raw JWT */ }
                        }
                        // If parsed is an ApiToken object: { success?, token: <jwt|string|nested>, refreshToken: <guid> }
                        if (parsed && typeof parsed === 'object') {
                            // Capture refresh token FIRST so we don't lose it if we unwrap token below
                            if (parsed.refreshToken) refreshToken = parsed.refreshToken;

                            // Unwrap nested token if it looks like a JWT container object
                            if (typeof parsed.token === 'string' && parsed.token.split('.').length === 3) {
                                jwt = parsed.token;
                            } else if (parsed.jwt && typeof parsed.jwt === 'string') {
                                jwt = parsed.jwt;
                            } else if (typeof parsed.token === 'object' && parsed.token) {
                                // Rare case: nested object containing actual token field
                                if (typeof parsed.token.token === 'string') jwt = parsed.token.token;
                                if (!refreshToken && parsed.token.refreshToken) refreshToken = parsed.token.refreshToken;
                            }
                        }
                        // Fallbacks
                        if (!jwt && typeof parsed === 'string') {
                            jwt = parsed; // treat raw string as JWT
                        }
                        if (!jwt) {
                            jwt = raw; // last resort
                        }
                    } catch {
                        jwt = data.token; // fallback
                    }
                    // Debug (optional):
                    // console.debug('[login] extracted jwt length:', jwt?.length, 'has refresh:', !!refreshToken);

                    // Store JWT token using shared auth helper for consistency
                    localStorage.setItem('jwtToken', jwt);
                    if(window.mainAuth && jwt){
                        window.mainAuth.setAuthToken(jwt);
                    } else {
                        document.cookie = `authToken=${jwt}; max-age=${8 * 60 * 60}; path=/; SameSite=Lax; secure`;
                    }

                    if (refreshToken) {
                        localStorage.setItem('refreshToken', refreshToken);
                    } else {
                        localStorage.removeItem('refreshToken');
                    }

                    const usernameFromJwt = getUsernameFromToken(jwt) || username;

                    // Show success notification
                    //notifications.success(`Welcome back, ${usernameFromJwt}!`);
                    console.error("Before show home page.");
                    showHomePage();

                } else {
                    //notifications.error('Login failed. Please check your username and password.');
                }
            } catch (error) {
                //notifications.error('An unexpected error occurred. Please try again later.');
            }
        }

function showHomePage() {
    console.log("shwowing home page");
    const content = ensurePageContent();
        if (!content) return;
        fetch('dashboard.html')
        .then(r => {
            if(!r.ok){ console.warn('home.html fetch failed status', r.status); throw new Error('bad status'); }
            return r.text();
        })
        .then(html => {
            content.innerHTML = html.replace(/\{BASE_URL\}/g, BASE_URL || '');
            setActiveNav('navHomeBtn');
            if (window.loadHomeExtras) {
                // Defer to ensure DOM nodes are painted
                setTimeout(()=>{
                    try { window.loadHomeExtras(); } catch(e){ console.error('loadHomeExtras error', e); }
                }, 0);
            }
    })
.catch(err => { console.error('Failed to load home.html', err); content.innerHTML = '<p style="color:#f66">Failed to load home content.</p>'; });
}

(function(){
    // Use global BASE_URL if defined (other scripts set this) else default to relative root
    const ROOT = (typeof BASE_URL === 'string' && BASE_URL) ? BASE_URL : '/';
    const REFRESH_ENDPOINT = ROOT + 'app/refreshtoken';
    // Access token lifetime (seconds) must match server-issued JWT expiry (1 hour)
    const ACCESS_LIFETIME_SECONDS = 60 * 60; // 1 hour
    // Refresh skew: refresh 10 seconds before expiry to avoid race with server
    const REFRESH_SKEW_SECONDS = 10; // 10s before expiry

    function parseJwt(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g,'+').replace(/_/g,'/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(c=>'%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)).join(''));
            return JSON.parse(jsonPayload);
        } catch { return null; }
    }
    function getCookie(name){
        const m = document.cookie.split('; ').find(r=>r.startsWith(name+'='));
        return m ? m.split('=')[1] : null;
    }
    function setAuthToken(token){
        const isHttps = (typeof location !== 'undefined') && location.protocol === 'https:';
        if(!token){
            // Clear cookie and local storage
            document.cookie=`authToken=; max-age=0; path=/; SameSite=Lax${isHttps ? '; secure' : ''}`;
            localStorage.removeItem('jwtToken');
            return;
        }
        // Set cookie (secure only on https) and persist in localStorage for fallback
        document.cookie=`authToken=${token}; max-age=${ACCESS_LIFETIME_SECONDS}; path=/; SameSite=Lax${isHttps ? '; secure' : ''}`;
        localStorage.setItem('jwtToken', token);
    }
    function getAccessToken(){
        // Prefer cookie; fallback to localStorage for HTTP/dev where secure cookie won't set
        return getCookie('authToken') || localStorage.getItem('jwtToken');
    }
    function getRefreshToken(){
        return localStorage.getItem('refreshToken');
    }
    let refreshing = null;
    async function performRefresh(){
        //console.debug('[auth] performRefresh invoked');
        const username = (function(){
            const t = getAccessToken();
            if(t){ const p = parseJwt(t); if(p && p.username) return p.username; }
            // Fallback: stored loginData
            try { const ld = JSON.parse(localStorage.getItem('loginData')||'{}'); return ld.username; } catch { return null; }
        })();
        const refreshToken = getRefreshToken();
        if(!username || !refreshToken){
            //console.debug('[auth] performRefresh abort: missing username or refresh token');
            return null;
        }
        try {
            //console.debug('[auth] sending refresh request');
            const resp = await fetch(REFRESH_ENDPOINT, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, refreshToken }) });
            if(!resp.ok) {
                let txt='';
                try { txt = await resp.text(); } catch {}
                //console.debug('[auth] refresh failed status', resp.status, 'body:', txt?.slice(0,200));
                return null;
            }
            const data = await resp.json();
            if(data && data.token){
                //console.debug('[auth] refresh successful, setting new token');
                setAuthToken(data.token);
                if(data.refreshToken){ 
                    localStorage.setItem('refreshToken', data.refreshToken); 
                    //console.debug('[auth] refresh token rotated');
                }
                // Schedule next refresh based on the NEW token, not immediately
                setTimeout(() => scheduleProactiveRefresh(), 1000);
                return data.token;
            }
        } catch (e) {
            //console.debug('[auth] refresh exception', e);
            return null;
        }
        return null;
    }
    function scheduleProactiveRefresh(){
        const token = getAccessToken();
        if(!token) {
            //console.debug('[auth] scheduleProactiveRefresh: no token, skipping');
            return;
        }
        const payload = parseJwt(token); 
        if(!payload || !payload.exp) {
            //console.debug('[auth] scheduleProactiveRefresh: invalid token payload, skipping');
            return;
        }
        const now = Math.floor(Date.now()/1000);
        const refreshAt = (payload.exp - REFRESH_SKEW_SECONDS) - now;
        //console.debug('[auth] scheduleProactiveRefresh: token expires in', payload.exp - now, 'seconds, will refresh in', refreshAt, 'seconds');

        // If the computed refresh time is <= 0 (already inside skew window) trigger immediately
        if(refreshAt <= 0){ 
            //console.debug('[auth] scheduleProactiveRefresh: token already in skew window, triggering immediate refresh');
            triggerRefresh(); 
            return; 
        }

        // Don't schedule if refresh time is too far in future (sanity check)
        if(refreshAt > 3600) {
            //console.debug('[auth] scheduleProactiveRefresh: refresh time too far in future, skipping schedule');
            return;
        }

        setTimeout(triggerRefresh, refreshAt*1000);
        //console.debug('[auth] scheduleProactiveRefresh: scheduled refresh in', refreshAt, 'seconds');
    }
    async function triggerRefresh(){
        if(refreshing){
            //console.debug('[auth] refresh already in progress, returning existing promise');
            return refreshing;
        }
        //console.debug('[auth] triggerRefresh starting new refresh');
        refreshing = performRefresh().finally(()=>{ 
            //console.debug('[auth] refresh cycle complete'); 
            refreshing=null; 
            // CRITICAL FIX: Don't immediately reschedule after refresh, let bootstrap or other logic handle it
            // This was causing the rapid refresh loop
            // scheduleProactiveRefresh(); 
        });
        return refreshing;
    }

    async function authFetch(url, options={}){
        options.headers = options.headers || {};
        let token = getAccessToken();
        if(token){ options.headers['Authorization'] = 'Bearer '+token; }
        let resp = await fetch(url, { ...options, credentials:'omit' });
        if(resp.status === 401){
            // Prevent multiple concurrent refresh attempts from rapid polling
            if(refreshing){
                //console.debug('[auth] 401 detected but refresh already in progress, waiting...');
                await refreshing;
                token = getAccessToken();
            } else {
                //console.debug('[auth] 401 detected, triggering refresh');
                const newToken = await triggerRefresh();
                token = newToken;
            }
            if(token){
                options.headers['Authorization'] = 'Bearer '+token;
                resp = await fetch(url, { ...options, credentials:'omit' });
            }
        }
        return resp;
    }

    function bootstrapAuth(){
        const token = getAccessToken();
        // If no access token but we have a refresh token + username info, try immediate refresh
        if(!token && getRefreshToken()){
            //console.debug('[auth] bootstrap: no access token present, attempting refresh');
            triggerRefresh();
            return; // triggerRefresh will reschedule
        }
        // If token exists but already inside skew window, refresh now
        if(token){
            const payload = parseJwt(token);
            if(payload && payload.exp){
                const now = Math.floor(Date.now()/1000);
                if((payload.exp - now) <= REFRESH_SKEW_SECONDS){
                    //console.debug('[auth] bootstrap: token inside skew window, refreshing now');
                    triggerRefresh();
                    return;
                }
            }
        }
        scheduleProactiveRefresh();
    }

    // Kick off bootstrap logic on load
    window.addEventListener('load', bootstrapAuth);

    // Backwards compatibility shim: legacy code expects global getAuthToken()
    if(!window.getAuthToken){
        window.getAuthToken = getAccessToken; // deprecated alias
    }
    window.authFetch = authFetch;
})();
 

