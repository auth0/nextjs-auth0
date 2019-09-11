"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const cookies_1 = require("../utils/cookies");
function createLogoutUrl(settings) {
    return (`https://${settings.domain}/v2/logout?`
        + `client_id=${settings.clientId}`
        + `&returnTo=${encodeURIComponent(settings.postLogoutRedirectUri)}`);
}
function logoutHandler(settings, sessionSettings) {
    return (_, res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!res) {
            throw new Error('Response is not available');
        }
        // Remove the cookies
        cookies_1.setCookies(res, [
            {
                name: 'a0:state',
                value: '',
                maxAge: -1
            },
            {
                name: sessionSettings.cookieName,
                value: '',
                maxAge: -1,
                path: sessionSettings.cookiePath
            }
        ]);
        // Redirect to the logout endpoint.
        res.writeHead(302, {
            Location: createLogoutUrl(settings)
        });
        res.end();
    });
}
exports.default = logoutHandler;
//# sourceMappingURL=logout.js.map