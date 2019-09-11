"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const openid_client_1 = require("openid-client");
function getClient(settings) {
    let issuer = null;
    let client = null;
    return () => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!issuer) {
            issuer = yield openid_client_1.Issuer.discover(`https://${settings.domain}/`);
        }
        if (!client) {
            client = new issuer.Client({
                client_id: settings.clientId,
                client_secret: settings.clientSecret,
                redirect_uris: [settings.redirectUri],
                response_types: ['code']
            });
        }
        return client;
    });
}
exports.default = getClient;
//# sourceMappingURL=oidc-client.js.map