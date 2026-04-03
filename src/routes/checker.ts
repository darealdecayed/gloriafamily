import { Router } from 'express'
import { checkProxy } from '../controllers/proxy'
import { authenticate } from '../middleware/auth'

const router = Router()

router.get('/check/:domain', authenticate, checkProxy)

export default router
