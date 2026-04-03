import * as tls from 'tls'
import * as crypto from 'crypto'
import * as https from 'https'
import * as http from 'http'
import WebSocket from 'ws'
import { LatencyStats, ProxyDetectionResult } from './types'

export class ProxyDetector {
  async getTLSFingerprint(domain: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(443, domain, { servername: domain })
      const startTime = process.hrtime.bigint()
      
      socket.on('secureConnect', () => {
        const cert = socket.getPeerCertificate()
        const fingerprint = crypto.createHash('sha256').update(cert.raw).digest('hex')
        const endTime = process.hrtime.bigint()
        socket.destroy()
        resolve(fingerprint)
      })
      
      socket.on('error', (err: Error) => {
        reject(err)
      })
      
      socket.setTimeout(5000, () => {
        socket.destroy()
        reject(new Error('TLS handshake timeout'))
      })
    })
  }

  async measureHandshakeTime(domain: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const startTime = process.hrtime.bigint()
      const socket = tls.connect(443, domain, { servername: domain })
      
      socket.on('secureConnect', () => {
        const endTime = process.hrtime.bigint()
        const handshakeTime = Number(endTime - startTime) / 1000000
        socket.destroy()
        resolve(handshakeTime)
      })
      
      socket.on('error', () => {
        reject(new Error('Handshake failed'))
      })
      
      socket.setTimeout(5000, () => {
        socket.destroy()
        reject(new Error('Handshake timeout'))
      })
    })
  }

  async makeHTTPSRequest(domain: string): Promise<{ headers: http.IncomingHttpHeaders; body: string; latency: number }> {
    return new Promise((resolve, reject) => {
      const startTime = process.hrtime.bigint()
      
      const req = https.request({
        hostname: domain,
        port: 443,
        path: '/',
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0' }
      }, (res: http.IncomingMessage) => {
        let body = ''
        res.on('data', (chunk: Buffer) => {
          body += chunk
        })
        
        res.on('end', () => {
          const endTime = process.hrtime.bigint()
          const latency = Number(endTime - startTime) / 1000000
          resolve({
            headers: res.headers,
            body: body,
            latency: latency
          })
        })
      })
      
      req.on('error', (err: Error) => reject)
      req.setTimeout(10000, () => {
        req.destroy()
        reject(new Error('Request timeout'))
      })
      
      req.end()
    })
  }

  async checkBareMux(domain: string): Promise<boolean> {
    try {
      const response = await this.makeHTTPSRequest(domain)
      const body = response.body.toLowerCase()
      
      const proxyIndicators = [
        'proxy server',
        'tunnel connection',
        'socket forward',
        'http tunnel',
        'websocket proxy'
      ]
      
      return proxyIndicators.some(indicator => body.includes(indicator))
    } catch (error) {
      return false
    }
  }

  async checkWispServers(domain: string): Promise<boolean> {
    try {
      const response = await this.makeHTTPSRequest(domain)
      const body = response.body.toLowerCase()
      
      const wispIndicators = [
        'websocket tunnel',
        'multiplexed connection',
        'proxy tunnel',
        'socket proxy',
        'tunnel server'
      ]
      
      return wispIndicators.some(indicator => body.includes(indicator))
    } catch (error) {
      return false
    }
  }

  async checkGameSiteContent(domain: string): Promise<boolean> {
    try {
      const response = await this.makeHTTPSRequest(domain)
      const body = response.body.toLowerCase()
      const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.toLowerCase() || ''
      
      const gameIndicators = [
        'unblocked games',
        'school games',
        'games for school',
        'play games',
        'online games',
        'flash games',
        'html5 games',
        'arcade games',
        'multiplayer games',
        'browser games',
        'free games',
        'game portal',
        'gaming site',
        'educational games',
        'math games',
        'learning games',
        'fun games',
        'kids games',
        'student games',
        'classroom games'
      ]
      
      const gameKeywords = [
        'game', 'games', 'play', 'player', 'gaming', 'arcade', 'puzzle',
        'action', 'adventure', 'strategy', 'rpg', 'mmo', 'fps', 'multiplayer',
        'singleplayer', 'campaign', 'level', 'score', 'highscore', 'achievement',
        'leaderboard', 'tournament', 'competition', 'match', 'round', 'stage'
      ]
      
      const gamePlatforms = [
        'unity', 'webgl', 'flash', 'html5', 'canvas', 'webassembly', 'wasm',
        'construct', 'godot', 'phaser', 'three.js', 'babylonjs', 'playcanvas'
      ]
      
      const titleScore = gameIndicators.filter(indicator => title.includes(indicator)).length * 0.3
      const contentScore = gameIndicators.filter(indicator => body.includes(indicator)).length * 0.2
      const keywordScore = gameKeywords.filter(keyword => body.includes(keyword)).length * 0.05
      const platformScore = gamePlatforms.filter(platform => body.includes(platform)).length * 0.15
      
      const totalScore = titleScore + contentScore + keywordScore + platformScore
      
      return totalScore > 0.4
    } catch (error) {
      return false
    }
  }

  analyzeDomainName(domain: string): number {
    const suspiciousPatterns = [
      /\d+/g,
      /[a-z]{15,}/,
      /[^a-zA-Z0-9.-]/,
      /(temp|test|proxy|vpn|tunnel|hide|anonymous|fake|mock|dummy|notsaying)/i,
      /(xyz|tk|ml|ga|cf|top|click|download|stream|watch|free|online|site|web)/i,
      /^[a-z]+\d+[a-z]+$/i,
      /\.{2,}/,
      /(games|play|fun|unblocked|school|work|bypass|proxy)/i,
      /(petezah|zah|peter|pete)/i,
      /(github|gitlab|bitbucket)/i,
      /(vercel|netlify|cloudflare|glitch)/i,
    ]

    let score = 0
    
    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(domain)) {
        score += 0.3
      }
    })
    
    if (domain.length > 25 || domain.length < 4) {
      score += 0.2
    }
    
    const consonantClusters = domain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi)
    if (consonantClusters && consonantClusters.length > 0) {
      score += 0.2
    }
    
    if (domain.includes('notsaying') || domain.includes('hidden') || domain.includes('secret')) {
      score += 0.8
    }
    
    if (domain.includes('games') && (domain.includes('unblocked') || domain.includes('school') || domain.includes('work'))) {
      score += 0.9
    }
    
    return Math.min(score, 1)
  }

  calculateHeaderEntropy(headers: http.IncomingHttpHeaders): number {
    const headerValues = Object.values(headers).filter(val => val !== undefined)
    const headerString = headerValues.join('')
    const frequency: { [key: string]: number } = {}
    
    for (const char of headerString) {
      frequency[char] = (frequency[char] || 0) + 1
    }
    
    let entropy = 0
    const length = headerString.length
    
    for (const char in frequency) {
      const probability = frequency[char] / length
      entropy -= probability * Math.log2(probability)
    }
    
    return entropy
  }

  calculateVariance(values: number[]): number {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length
    const squaredDiffs = values.map(val => Math.pow(val - mean, 2))
    return squaredDiffs.reduce((sum, val) => sum + val, 0) / values.length
  }

  async testWebSocketUpgrade(domain: string): Promise<boolean> {
    return new Promise((resolve) => {
      const wsUrl = `wss://${domain}`
      const ws = new WebSocket(wsUrl, {
        headers: { 'User-Agent': 'Mozilla/5.0' }
      })
      
      const timeout = setTimeout(() => {
        ws.terminate()
        resolve(false)
      }, 5000)
      
      ws.on('open', () => {
        clearTimeout(timeout)
        ws.close()
        resolve(true)
      })
      
      ws.on('error', () => {
        clearTimeout(timeout)
        resolve(false)
      })
    })
  }

  async analyzeDomain(domain: string): Promise<ProxyDetectionResult> {
    const numRequests = 5
    const tlsFingerprints: string[] = []
    const handshakeTimes: number[] = []
    const latencies: number[] = []
    const responseHashes: string[] = []
    const headerEntropies: number[] = []
    
    for (let i = 0; i < numRequests; i++) {
      try {
        const fingerprint = await this.getTLSFingerprint(domain)
        tlsFingerprints.push(fingerprint)
        
        const handshakeTime = await this.measureHandshakeTime(domain)
        handshakeTimes.push(handshakeTime)
        
        const response = await this.makeHTTPSRequest(domain)
        latencies.push(response.latency)
        
        const responseHash = crypto.createHash('sha256').update(response.body).digest('hex')
        responseHashes.push(responseHash)
        
        const entropy = this.calculateHeaderEntropy(response.headers)
        headerEntropies.push(entropy)
      } catch (error) {
        continue
      }
    }
    
    const uniqueFingerprints = new Set(tlsFingerprints).size
    const uniqueResponseHashes = new Set(responseHashes).size
    const avgHeaderEntropy = headerEntropies.reduce((sum, val) => sum + val, 0) / headerEntropies.length || 0
    
    const latencyStats: LatencyStats = {
      min: Math.min(...latencies),
      max: Math.max(...latencies),
      avg: latencies.reduce((sum, val) => sum + val, 0) / latencies.length || 0,
      variance: this.calculateVariance(latencies)
    }
    
    const handshakeVariance = this.calculateVariance(handshakeTimes)
    const websocketUpgrade = await this.testWebSocketUpgrade(domain)
    const isBareMux = await this.checkBareMux(domain)
    const isWispServer = await this.checkWispServers(domain)
    const isGameSite = await this.checkGameSiteContent(domain)
    const domainSuspicionScore = this.analyzeDomainName(domain)
    
    let anomalyScore = 0
    
    anomalyScore += domainSuspicionScore * 0.7
    
    if (uniqueFingerprints > 1) {
      anomalyScore += uniqueFingerprints * 0.4
    }
    
    if (handshakeVariance > 100) {
      anomalyScore += Math.min(handshakeVariance / 100, 1) * 0.4
    }
    
    if (latencyStats.variance > 800) {
      anomalyScore += Math.min(latencyStats.variance / 800, 1) * 0.3
    }
    
    if (uniqueResponseHashes > 2) {
      anomalyScore += (uniqueResponseHashes - 2) * 0.2
    }
    
    if (!websocketUpgrade) {
      anomalyScore += 0.2
    }
    
    if (isBareMux) {
      anomalyScore += 0.6
    }
    
    if (isWispServer) {
      anomalyScore += 0.8
    }
    
    if (isGameSite) {
      anomalyScore += 0.7
    }
    
    const proxyLikely = anomalyScore > 0.3
    
    return {
      domain,
      tlsFingerprints,
      handshakeTimes,
      latencyStats,
      headerEntropy: avgHeaderEntropy,
      responseHashConsistency: uniqueResponseHashes === 1,
      websocketUpgrade,
      anomalyScore,
      proxyLikely
    }
  }
}
