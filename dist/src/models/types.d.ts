export interface LatencyStats {
    min: number;
    max: number;
    avg: number;
    variance: number;
}
export interface ProxyDetectionResult {
    domain: string;
    tlsFingerprint: string;
    handshakeTime: number;
    headerEntropy: number;
    headerVariance: number;
    wispCheck: boolean;
    bareMuxCheck: boolean;
    domainScore: number;
    websocketUpgrade: boolean;
    gameContent: boolean;
    anomalyScore: number;
    proxyLikely: boolean;
    error?: string;
}
//# sourceMappingURL=types.d.ts.map