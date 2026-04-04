/**
 * Reference: AgentPin credential extraction as Express middleware.
 *
 * Usage:
 *   npm install express agentpin
 *   node examples/express_middleware.js
 *
 * This is example code — copy and adapt for your own server.
 */

import express from 'express';
import { httpExtractCredential } from 'agentpin';

/**
 * Express middleware that extracts an AgentPin credential from the
 * Authorization header and attaches it to req.agentpinCredential.
 */
function agentpinAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) {
        return res.status(401).json({ error: 'Missing Authorization header' });
    }

    try {
        req.agentpinCredential = httpExtractCredential(auth);
    } catch (err) {
        return res.status(401).json({ error: err.message });
    }

    // In production, verify the credential here:
    //   import { verifyCredentialOffline } from 'agentpin';
    //   const result = verifyCredentialOffline(jwt, discoveryDoc, ...);
    //   if (!result.valid) return res.status(403).json({ error: result.error });

    next();
}

const app = express();

app.get('/protected', agentpinAuth, (req, res) => {
    const jwt = req.agentpinCredential;
    res.json({ message: `Authenticated with credential: ${jwt.slice(0, 20)}...` });
});

app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Listening on http://127.0.0.1:${port}`);
});
