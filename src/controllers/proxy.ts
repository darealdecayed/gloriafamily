import { Response } from 'express'
import { ProxyDetector } from '../models/detector'

export const checkProxy = async (req: any, res: Response) => {
  try {
    const encodedDomain = req.params.encoded
    if (!encodedDomain) {
      return res.status(400).json({ error: 'Domain required' })
    }

    const decodedDomain = Buffer.from(encodedDomain, 'base64').toString()
    let domain = decodedDomain.replace(/"/g, '')
    
    if (domain.includes('/')) {
      domain = domain.split('/')[0]
    }
    
    if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' })
    }
    
    const detector = new ProxyDetector()
    const result = await detector.analyzeDomain(domain)
    
    const response = {
      site: domain,
      status: result.proxyLikely ? "blocked" : "unblocked",
      response: `${result.latencyStats.avg.toFixed(2)}ms`
    }

    console.log(`Check logged: ${domain} - ${response.status}`)
    
    res.json(response)
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' })
  }
}
