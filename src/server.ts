import dotenv from 'dotenv'
dotenv.config()

import express, { Request } from 'express'
import { config } from './config/env'
import checkerRoutes from './routes/checker'

declare global {
  namespace Express {
    interface Request {
      startTime?: number
    }
  }
}

const app = express()

app.use(express.json())

app.use((req, res, next) => {
  req.startTime = Date.now()
  next()
})

app.use('/v1/solstice', checkerRoutes)

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`)
})

export default app
