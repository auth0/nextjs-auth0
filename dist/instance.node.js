"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const handlers_1 = tslib_1.__importDefault(require("./handlers"));
const oidc_client_1 = tslib_1.__importDefault(require("./utils/oidc-client"));
const cookie_store_1 = tslib_1.__importDefault(require("./session/cookie-store"));
const settings_1 = tslib_1.__importDefault(require("./session/cookie-store/settings"));
function createInstance(settings) {
    if (!settings.session) {
        throw new Error('The session configuration is required');
    }
    const clientProvider = oidc_client_1.default(settings);
    const sessionSettings = new settings_1.default(settings.session);
    const store = new cookie_store_1.default(sessionSettings);
    return {
        handleLogin: handlers_1.default.LoginHandler(settings, clientProvider),
        handleLogout: handlers_1.default.LogoutHandler(settings, sessionSettings),
        handleCallback: handlers_1.default.CallbackHandler(settings, clientProvider, store),
        handleProfile: handlers_1.default.ProfileHandler(store),
        getSession: handlers_1.default.SessionHandler(store)
    };
}
exports.default = createInstance;
//# sourceMappingURL=instance.node.js.map