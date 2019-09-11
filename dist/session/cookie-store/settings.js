"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class CookieSessionStoreSettings {
    constructor(settings) {
        this.cookieSecret = settings.cookieSecret;
        if (!this.cookieSecret || !this.cookieSecret.length) {
            throw new Error('The cookieSecret setting is empty or null');
        }
        if (this.cookieSecret.length < 32) {
            throw new Error('The cookieSecret should be at least 32 characters long');
        }
        this.cookieName = settings.cookieName || 'a0:session';
        if (!this.cookieName || !this.cookieName.length) {
            throw new Error('The cookieName setting is empty or null');
        }
        this.cookieLifetime = settings.cookieLifetime || 60 * 60 * 8;
        this.cookiePath = settings.cookiePath || '/';
        if (!this.cookiePath || !this.cookiePath.length) {
            throw new Error('The cookiePath setting is empty or null');
        }
        this.storeIdToken = settings.storeIdToken || false;
        this.storeAccessToken = settings.storeAccessToken || false;
    }
}
exports.default = CookieSessionStoreSettings;
//# sourceMappingURL=settings.js.map