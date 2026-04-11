"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Categorizer = void 0;
const https_1 = __importDefault(require("https"));
const BLOCKED_CATEGORIES = ['adult', 'pornography', 'adult-content', 'nsfw', 'malware', 'phishing'];
class Categorizer {
    async categorize(domain) {
        const cleanDomain = domain.replace(/^www\./, '');
        const dynamicBlockResult = this.checkDynamicBlocklist(cleanDomain);
        if (dynamicBlockResult.isBlocked) {
            return dynamicBlockResult;
        }
        const result = await Promise.race([
            this.queryCloudflareRadar(cleanDomain),
            new Promise(resolve => setTimeout(() => resolve({
                domain: cleanDomain,
                category: 'uncategorized',
                confidence: 0,
                isBlocked: false,
                source: 'timeout'
            }), 3000))
        ]);
        return result;
    }
    checkDynamicBlocklist(domain) {
        const socialMediaList = (process.env.BLOCKED_SOCIAL_MEDIA || '').split(',').filter(Boolean);
        const otherBlockedList = (process.env.BLOCKED_CATEGORIES_DYNAMIC || '').split(',').filter(Boolean);
        const domainLower = domain.toLowerCase();
        for (const blocked of socialMediaList) {
            if (domainLower.includes(blocked.trim()) || domainLower.startsWith(blocked.trim())) {
                return {
                    domain: domain,
                    category: 'social-media',
                    confidence: 0.9,
                    isBlocked: true,
                    source: 'dynamic'
                };
            }
        }
        for (const blocked of otherBlockedList) {
            if (domainLower.includes(blocked.trim()) || domainLower.startsWith(blocked.trim())) {
                return {
                    domain: domain,
                    category: blocked.trim(),
                    confidence: 0.9,
                    isBlocked: true,
                    source: 'dynamic'
                };
            }
        }
        return {
            domain: domain,
            category: 'uncategorized',
            confidence: 0,
            isBlocked: false,
            source: 'dynamic'
        };
    }
    queryCloudflareRadar(domain) {
        return new Promise((resolve) => {
            const options = {
                hostname: 'api.cloudflare.com',
                path: `/client/v4/radar/http/top/locations?limit=1000`,
                method: 'GET',
                timeout: 2500,
                headers: {
                    'User-Agent': 'Mozilla/5.0'
                }
            };
            const req = https_1.default.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk.toString();
                });
                res.on('end', () => {
                    try {
                        this.checkDomainReputation(domain).then(result => resolve(result));
                    }
                    catch (error) {
                        resolve({
                            domain: domain,
                            category: 'uncategorized',
                            confidence: 0,
                            isBlocked: false,
                            source: 'timeout'
                        });
                    }
                });
            });
            req.on('error', () => {
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.on('timeout', () => {
                req.destroy();
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.end();
        });
    }
    checkDomainReputation(domain) {
        return new Promise((resolve) => {
            const options = {
                hostname: 'dns.google',
                path: `/resolve?name=${encodeURIComponent(domain)}&type=A`,
                method: 'GET',
                timeout: 2000,
                headers: {
                    'User-Agent': 'Mozilla/5.0'
                }
            };
            const req = https_1.default.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk.toString();
                });
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        const categoryData = this.categorizeByReputation(domain, json);
                        resolve({
                            domain: domain,
                            category: categoryData.category,
                            confidence: categoryData.confidence,
                            isBlocked: categoryData.isBlocked,
                            source: 'cloudflare'
                        });
                    }
                    catch (error) {
                        resolve({
                            domain: domain,
                            category: 'uncategorized',
                            confidence: 0,
                            isBlocked: false,
                            source: 'timeout'
                        });
                    }
                });
            });
            req.on('error', () => {
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.on('timeout', () => {
                req.destroy();
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.end();
        });
    }
    categorizeByReputation(domain, dnsData) {
        const adultIndicators = [
            'adult', 'sex', 'porn', 'nude', 'xxx', 'cam', 'strip', 'escort',
            'dating', 'hookup', 'fetish', 'mature', 'erotic', 'peep', 'live-sex',
            'webcam', 'nsfw'
        ];
        const maliciousIndicators = [
            'malware', 'phishing', 'scam', 'phish', 'botnet', 'trojan',
            'virus', 'ransomware', 'spyware', 'adware', 'unwanted'
        ];
        const searchEngines = ['google', 'bing', 'yahoo', 'duckduckgo', 'startpage', 'ecosia'];
        const videoStreaming = ['youtube', 'vimeo', 'dailymotion', 'twitch', 'netflix', 'hulu', 'prime', 'disney'];
        const news = ['bbc', 'cnn', 'reuters', 'apnews', 'nytimes', 'guardian', 'washingtonpost', 'theverge', 'wired'];
        const ecommerce = ['amazon', 'ebay', 'shopify', 'etsy', 'aliexpress', 'walmart'];
        const communication = ['gmail', 'outlook', 'protonmail', 'slack', 'discord', 'telegram', 'whatsapp'];
        const learning = ['coursera', 'udemy', 'edx', 'skillshare', 'codecademy', 'khan'];
        const domainLower = domain.toLowerCase();
        const hasAdultIndicator = adultIndicators.some(indicator => domainLower.includes(indicator));
        const hasMaliciousIndicator = maliciousIndicators.some(indicator => domainLower.includes(indicator));
        if (hasAdultIndicator) {
            return {
                category: 'adult',
                confidence: 0.85,
                isBlocked: true
            };
        }
        if (hasMaliciousIndicator) {
            return {
                category: 'malware',
                confidence: 0.90,
                isBlocked: true
            };
        }
        if (searchEngines.some(e => domainLower.includes(e))) {
            return {
                category: 'search-engine',
                confidence: 0.9,
                isBlocked: false
            };
        }
        if (videoStreaming.some(v => domainLower.includes(v))) {
            return {
                category: 'video-streaming',
                confidence: 0.9,
                isBlocked: false
            };
        }
        if (news.some(n => domainLower.includes(n))) {
            return {
                category: 'news',
                confidence: 0.85,
                isBlocked: false
            };
        }
        if (ecommerce.some(e => domainLower.includes(e))) {
            return {
                category: 'ecommerce',
                confidence: 0.85,
                isBlocked: false
            };
        }
        if (communication.some(c => domainLower.includes(c))) {
            return {
                category: 'communication',
                confidence: 0.85,
                isBlocked: false
            };
        }
        if (learning.some(l => domainLower.includes(l))) {
            return {
                category: 'learning',
                confidence: 0.85,
                isBlocked: false
            };
        }
        return {
            category: 'uncategorized',
            confidence: 0.5,
            isBlocked: true
        };
    }
    static isBlockedCategory(category) {
        return BLOCKED_CATEGORIES.includes(category.toLowerCase());
    }
    static getBlockedCategories() {
        return [...BLOCKED_CATEGORIES];
    }
}
exports.Categorizer = Categorizer;
//# sourceMappingURL=categorizer.js.map