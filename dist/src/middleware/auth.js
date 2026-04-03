"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticate = void 0;
const authenticate = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const studentEmail = req.headers['x-student-email'];
    const license = req.headers['x-license'];
    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }
    if (!/^[0-9]{10}$/.test(apiKey)) {
        return res.status(401).json({ error: 'Invalid API key format' });
    }
    if (!studentEmail) {
        return res.status(403).json({ error: 'Student email required' });
    }
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(edu|k12\.[a-z]{2}\.us|dev)$/;
    if (!emailRegex.test(studentEmail)) {
        return res.status(403).json({ error: 'Invalid student email format' });
    }
    if (!license) {
        return res.status(403).json({ error: 'License required' });
    }
    if (!/^[0-9]{10}$/.test(license)) {
        return res.status(403).json({ error: 'Invalid license format' });
    }
    ;
    req.apiKey = apiKey;
    req.studentEmail = studentEmail;
    req.license = license;
    next();
};
exports.authenticate = authenticate;
//# sourceMappingURL=auth.js.map