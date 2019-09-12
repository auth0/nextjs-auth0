"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const base64url_1 = tslib_1.__importDefault(require("base64url"));
const crypto_1 = require("crypto");
const version_1 = tslib_1.__importDefault(require("../version"));
const cookies_1 = require("../utils/cookies");
function telemetry() {
    const bytes = Buffer.from(JSON.stringify({
        name: 'nextjs-auth0',
        version: version_1.default
    }));
    return bytes
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
function loginHandler(settings, clientProvider) {
    return (_req, res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!res) {
            throw new Error('Response is not available');
        }
        // Generate the state
        const state = base64url_1.default(crypto_1.randomBytes(48));
        // Create the authorization url.
        const client = yield clientProvider();
        const authorizationUrl = client.authorizationUrl({
            redirect_uri: settings.redirectUri,
            scope: settings.scope,
            response_type: 'code'
        });
        // Set the necessary cookies
        cookies_1.setCookies(res, [
            {
                name: 'a0:state',
                value: state,
                maxAge: 60 * 60
            }
        ]);
        // Redirect to the authorize endpoint.
        res.writeHead(302, {
            Location: `${authorizationUrl}&state=${state}&auth0Client=${telemetry()}`
        });
        res.end();
    });
}
exports.default = loginHandler;
//# sourceMappingURL=login.js.map