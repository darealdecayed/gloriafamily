"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkProxy = void 0;
const detector_1 = require("../models/detector");
const checkProxy = async (req, res) => {
    try {
        const domain = req.params.domain;
        if (!domain) {
            return res.status(400).json({ error: 'Domain required' });
        }
        let cleanDomain = domain.replace(/"/g, '');
        if (cleanDomain.includes('/')) {
            cleanDomain = cleanDomain.split('/')[0];
        }
        if (!cleanDomain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleanDomain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        const detector = new detector_1.ProxyDetector();
        const result = await detector.analyzeDomain(cleanDomain);
        const response = {
            site: cleanDomain,
            status: result.proxyLikely ? "blocked" : "unblocked",
            response: `${result.latencyStats.avg.toFixed(2)}ms`
        };
        console.log(`Check logged: ${cleanDomain} - ${response.status}`);
        res.json(response);
    }
    catch (error) {
        res.status(500).json({ error: 'Analysis failed' });
    }
};
exports.checkProxy = checkProxy;
//# sourceMappingURL=proxy.js.map