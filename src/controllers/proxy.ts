import { Response } from 'express'
import { ProxyDetector } from '../models/detector'

export const checkProxy = async (req: any, res: Response) => {
  try {
    const domain = req.params.domain
    if (!domain) {
      return res.status(400).json({ error: 'Domain required' })
    }

    let cleanDomain = domain.replace(/"/g, '')
    
    if (cleanDomain.includes('/')) {
      cleanDomain = cleanDomain.split('/')[0]
    }
    
    if (!cleanDomain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleanDomain)) {
      return res.status(400).json({ error: 'Invalid domain format' })
    }
    
    const detector = new ProxyDetector()
    const result = await detector.analyzeDomain(cleanDomain)
    
    const response = {
      site: cleanDomain,
      status: result.proxyLikely ? "blocked" : "unblocked",
      response: `${Date.now() - req.startTime}ms`
    }

    console.log(`Check logged: ${cleanDomain} - ${response.status}`)
    
    res.json(response)
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' })
  }
}
