"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const proxy_1 = require("../controllers/proxy");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.get('/check/:domain', auth_1.authenticate, proxy_1.checkProxy);
exports.default = router;
//# sourceMappingURL=checker.js.map