import * as http from 'http';
import { ProxyDetectionResult } from './types';
export declare class ProxyDetector {
    getTLSFingerprint(domain: string): Promise<string>;
    measureHandshakeTime(domain: string): Promise<number>;
    makeHTTPSRequest(domain: string): Promise<{
        headers: http.IncomingHttpHeaders;
        body: string;
        latency: number;
    }>;
    checkBareMux(domain: string): Promise<boolean>;
    checkWispServers(domain: string): Promise<boolean>;
    checkGameSiteContent(domain: string): Promise<boolean>;
    analyzeDomainName(domain: string): number;
    calculateStringEntropy(str: string): number;
    calculateHeaderEntropy(headers: http.IncomingHttpHeaders): number;
    calculateVariance(values: number[]): number;
    testWebSocketUpgrade(domain: string): Promise<boolean>;
    analyzeDomain(domain: string): Promise<ProxyDetectionResult>;
}
//# sourceMappingURL=detector.d.ts.map