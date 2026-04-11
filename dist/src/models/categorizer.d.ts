export interface CategoryResult {
    domain: string;
    category: string;
    confidence: number;
    isBlocked: boolean;
    source: 'cloudflare' | 'timeout' | 'dynamic';
}
export declare class Categorizer {
    categorize(domain: string): Promise<CategoryResult>;
    private checkDynamicBlocklist;
    private queryCloudflareRadar;
    private checkDomainReputation;
    private categorizeByReputation;
    static isBlockedCategory(category: string): boolean;
    static getBlockedCategories(): string[];
}
//# sourceMappingURL=categorizer.d.ts.map