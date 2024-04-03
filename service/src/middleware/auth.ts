import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { NextAction } from 'src/types'

const SECERT = crypto.randomBytes(32).toString('hex')

interface TokenPayload {
  valid: boolean
}

function isValidChatToken(tokenHeader: string) {
  try {
    const token = tokenHeader.replace('Bearer ', '').trim()
    const decode = jwt.verify(token, SECERT) as TokenPayload
    return !!decode.valid
  }
  catch {
    return false
  }
}

function createToken() {
  return jwt.sign({
    valid: true,
  }, SECERT, { expiresIn: '24h' })
}

const auth = async (req, res, next) => {
  try {
    const Authorization = req.header('Authorization')
    if (!Authorization || !Authorization.replace('Bearer ', '').trim())
      throw new Error('Error: 无访问权限 | No access rights')
    if (isValidChatToken(Authorization))
      next()
    else
      throw new Error('Error: 无访问权限 | No access rights')
  }
  catch (error) {
    res.send({ status: 'Unauthorized', message: error.message ?? 'Please authenticate.', data: null, action: NextAction.LOGIN })
  }
}

export { auth, isValidChatToken, createToken }
