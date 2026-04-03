import * as tls from 'tls'
import * as crypto from 'crypto'
import https from 'https'
import http from 'http'
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
      const metaDescription = body.match(/<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']/i)?.[1]?.toLowerCase() || ''
      const metaKeywords = body.match(/<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']/i)?.[1]?.toLowerCase() || ''
      
      const allText = title + ' ' + metaDescription + ' ' + metaKeywords + ' ' + body
      
      const interactiveElements = (body.match(/<iframe|<embed|<object|<canvas|<game|<play/gi) || []).length
      const scriptCount = (body.match(/<script/gi) || []).length
      const linkCount = (body.match(/<a\s+href/gi) || []).length
      const formCount = (body.match(/<form/gi) || []).length
      const buttonCount = (body.match(/<button/gi) || []).length
      
      const textEntropy = this.calculateStringEntropy(allText)
      const uniqueWords = new Set(allText.split(/\s+/)).size
      const avgWordLength = allText.split(/\s+/).reduce((sum, word) => sum + word.length, 0) / allText.split(/\s+/).length
      
      const domainEntropy = this.calculateStringEntropy(domain)
      const subdomainCount = domain.split('.').length - 2
      const numbers = domain.match(/\d/g)
      const consonantRatio = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length / domain.length
      
      const interactiveScore = Math.min((interactiveElements + formCount + buttonCount) * 0.1, 0.6)
      const scriptDensity = scriptCount > 15 ? 0.3 : 0
      const linkDensity = linkCount > 100 ? 0.2 : 0
      const entropyScore = textEntropy > 4.5 ? 0.3 : 0
      const vocabScore = uniqueWords > 500 ? 0.2 : 0
      const wordLengthScore = avgWordLength < 4 ? 0.2 : 0
      const domainComplexityScore = domainEntropy > 3.5 ? 0.2 : 0
      const subdomainScore = subdomainCount > 2 ? 0.1 : 0
      const numberScore = numbers && numbers.length > 2 ? 0.1 : 0
      const consonantScore = consonantRatio > 0.7 ? 0.1 : 0
      
      const totalScore = interactiveScore + scriptDensity + linkDensity + entropyScore + vocabScore + wordLengthScore + domainComplexityScore + subdomainScore + numberScore + consonantScore
      
      console.log(`Pure behavioral analysis for ${domain}: interactive=${interactiveElements}, forms=${formCount}, buttons=${buttonCount}, scripts=${scriptCount}, links=${linkCount}, entropy=${textEntropy.toFixed(2)}, words=${uniqueWords}, avgWordLen=${avgWordLength.toFixed(1)}, domainEntropy=${domainEntropy.toFixed(2)}, subdomains=${subdomainCount}, numbers=${numbers?.length || 0}, consonantRatio=${consonantRatio.toFixed(2)}, total=${totalScore.toFixed(1)}`)
      
      return totalScore > 0.5
    } catch (error) {
      return false
    }
  }

  analyzeDomainName(domain: string): number {
    let score = 0
    
    const entropy = this.calculateStringEntropy(domain)
    if (entropy > 3.5) {
      score += 0.3
    }
    
    if (domain.length > 25 || domain.length < 4) {
      score += 0.2
    }
    
    const numbers = domain.match(/\d/g)
    if (numbers && numbers.length > 2) {
      score += 0.3
    }
    
    const subdomainCount = domain.split('.').length - 2
    if (subdomainCount > 2) {
      score += 0.2
    }
    
    const consonantRatio = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length / domain.length
    if (consonantRatio > 0.7) {
      score += 0.2
    }
    
    return Math.min(score, 1)
  }

  calculateStringEntropy(str: string): number {
    const frequency: { [key: string]: number } = {}
    for (const char of str) {
      frequency[char] = (frequency[char] || 0) + 1
    }
    
    let entropy = 0
    for (const char in frequency) {
      const probability = frequency[char] / str.length
      entropy -= probability * Math.log2(probability)
    }
    
    return entropy
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
    try {
      const response = await this.makeHTTPSRequest(domain)
      
      const tlsFingerprint = await this.getTLSFingerprint(domain)
      const handshakeTime = await this.measureHandshakeTime(domain)
      const headerEntropy = this.calculateHeaderEntropy(response.headers)
      const headerVariance = this.calculateVariance([headerEntropy])
      const wispCheck = await this.checkWispServers(domain)
      const bareMuxCheck = await this.checkBareMux(domain)
      const domainScore = this.analyzeDomainName(domain)
      const websocketUpgrade = await this.testWebSocketUpgrade(domain)
      const gameContent = await this.checkGameSiteContent(domain)
      
      const anomalyScore = (
        (tlsFingerprint.length > 100 ? 0.2 : 0) +
        (handshakeTime > 200 ? 0.15 : 0) +
        (headerEntropy > 4.5 ? 0.15 : 0) +
        (headerVariance > 2.0 ? 0.1 : 0) +
        (wispCheck ? 0.25 : 0) +
        (bareMuxCheck ? 0.3 : 0) +
        (domainScore * 0.2) +
        (websocketUpgrade ? 0.2 : 0) +
        (gameContent ? 0.4 : 0)
      )
      
      const proxyLikely = anomalyScore > 0.4
      
      return {
        domain,
        tlsFingerprint,
        handshakeTime,
        headerEntropy,
        headerVariance,
        wispCheck,
        bareMuxCheck,
        domainScore,
        websocketUpgrade,
        gameContent,
        anomalyScore,
        proxyLikely
      }
    } catch (error) {
      return {
        domain,
        tlsFingerprint: '',
        handshakeTime: 0,
        headerEntropy: 0,
        headerVariance: 0,
        wispCheck: false,
        bareMuxCheck: false,
        domainScore: 0,
        websocketUpgrade: false,
        gameContent: false,
        anomalyScore: 0,
        proxyLikely: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }
}
