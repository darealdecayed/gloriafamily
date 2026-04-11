"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const env_1 = require("./config/env");
const checker_1 = __importDefault(require("./routes/checker"));
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((req, res, next) => {
    req.startTime = Date.now();
    next();
});
app.use('/v1/solstice', checker_1.default);
app.listen(env_1.config.port, () => {
    console.log(`Server running on port ${env_1.config.port}`);
});
exports.default = app;
//# sourceMappingURL=server.js.map