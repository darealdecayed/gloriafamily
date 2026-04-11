"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkProxy = void 0;
const detector_1 = require("../models/detector");
const categorizer_1 = require("../models/categorizer");
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
        const categorizer = new categorizer_1.Categorizer();
        const categoryResult = await categorizer.categorize(cleanDomain);
        if (categoryResult.isBlocked) {
            const elapsedTime = Date.now() - req.startTime;
            console.log(`Check logged: ${cleanDomain} - blocked`);
            return res.status(403).json({
                site: cleanDomain,
                status: 'blocked',
                category: categoryResult.category,
                response: `${elapsedTime}ms`
            });
        }
        const detector = new detector_1.ProxyDetector();
        const result = await Promise.race([
            detector.analyzeDomain(cleanDomain),
            new Promise((_resolve, reject) => setTimeout(() => reject(new Error('Analysis timeout')), 5000))
        ]).catch(() => ({
            domain: cleanDomain,
            proxyLikely: false,
            tlsFingerprint: '',
            handshakeTime: 0,
            headerEntropy: 0,
            headerVariance: 0,
            wispCheck: false,
            bareMuxCheck: false,
            domainScore: 0,
            websocketUpgrade: false,
            gameContent: false,
            anomalyScore: 0
        }));
        const response = {
            site: cleanDomain,
            category: categoryResult.category,
            status: result.proxyLikely ? "blocked" : "unblocked",
            response: `${Date.now() - req.startTime}ms`
        };
        console.log(`Check logged: ${cleanDomain} - ${response.status}`);
        res.json(response);
    }
    catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Analysis failed' });
    }
};
exports.checkProxy = checkProxy;
//# sourceMappingURL=proxy.js.map