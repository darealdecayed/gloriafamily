export interface LatencyStats {
  min: number
  max: number
  avg: number
  variance: number
}

export interface ProxyDetectionResult {
  domain: string
  tlsFingerprints: string[]
  handshakeTimes: number[]
  latencyStats: LatencyStats
  headerEntropy: number
  responseHashConsistency: boolean
  websocketUpgrade: boolean
  anomalyScore: number
  proxyLikely: boolean
}
