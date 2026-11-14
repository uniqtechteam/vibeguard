import express from 'express'
import cors from 'cors'

const app = express()
app.use(cors({ origin: true, credentials: true }))

export function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)
  res.setHeader('Access-Control-Allow-Credentials', 'true')
}
