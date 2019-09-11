"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function sessionHandler(sessionStore) {
    return (req) => {
        if (!req) {
            throw new Error('Request is not available');
        }
        return sessionStore.read(req);
    };
}
exports.default = sessionHandler;
//# sourceMappingURL=session.js.map