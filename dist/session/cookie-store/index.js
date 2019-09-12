"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const iron_1 = tslib_1.__importDefault(require("@hapi/iron"));
const session_1 = tslib_1.__importDefault(require("../session"));
const cookies_1 = require("../../utils/cookies");
class CookieSessionStore {
    constructor(settings) {
        this.settings = settings;
    }
    /**
     * Read the session from the cookie.
     * @param req HTTP request
     */
    read(req) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { cookieSecret, cookieName } = this.settings;
            const cookies = cookies_1.parseCookies(req);
            const cookie = cookies[cookieName];
            if (!cookie || cookie.length === 0) {
                return null;
            }
            const unsealed = yield iron_1.default.unseal(cookies[cookieName], cookieSecret, iron_1.default.defaults);
            if (!unsealed) {
                return null;
            }
            return unsealed;
        });
    }
    /**
     * Write the session to the cookie.
     * @param req HTTP request
     */
    save(_, res, session) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const { cookieSecret, cookieName, cookiePath, cookieLifetime } = this.settings;
            const { idToken, accessToken, user, createdAt } = session;
            const persistedSession = new session_1.default(user, createdAt);
            if (this.settings.storeIdToken && idToken) {
                persistedSession.idToken = idToken;
            }
            if (this.settings.storeAccessToken && accessToken) {
                persistedSession.accessToken = accessToken;
            }
            const encryptedSession = yield iron_1.default.seal(persistedSession, cookieSecret, iron_1.default.defaults);
            cookies_1.setCookie(res, {
                name: cookieName,
                value: encryptedSession,
                path: cookiePath,
                maxAge: cookieLifetime
            });
        });
    }
}
exports.default = CookieSessionStore;
//# sourceMappingURL=index.js.map