"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Session {
    constructor(user, createdAt) {
        this.user = user;
        if (createdAt) {
            this.createdAt = createdAt;
        }
        else {
            this.createdAt = Date.now();
        }
    }
}
exports.default = Session;
//# sourceMappingURL=session.js.map