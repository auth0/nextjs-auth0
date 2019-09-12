"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
function profileHandler(sessionStore) {
    return (req, res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!req) {
            throw new Error('Request is not available');
        }
        if (!res) {
            throw new Error('Response is not available');
        }
        const session = yield sessionStore.read(req);
        if (!session || !session.user) {
            res.status(401).json({ error: 'Not authenticated' });
            return;
        }
        res.json(session.user);
    });
}
exports.default = profileHandler;
//# sourceMappingURL=profile.js.map