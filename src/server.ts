import express from 'express'
import { config } from './config/env'
import checkerRoutes from './routes/checker'

const app = express()

app.use(express.json())

app.use('/v1/solstice', checkerRoutes)

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`)
})

export default app
