import type { VercelRequest, VercelResponse } from '@vercel/node'
import { tempoTestnet } from 'viem/chains'

type QueryRequest = {
  query: string
  signatures?: string[]
}

type QueryResponse = {
  cursor?: string
  columns: Array<{
    name: string
    pgtype: string
  }>
  rows: Array<Array<string | number | null>>
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const origin = req.headers.origin
  const allowedOrigins = ['https://docs.tempo.xyz', 'http://localhost:5173']

  // Allow preview deployments
  if (origin?.includes('vercel.app')) {
    allowedOrigins.push(origin)
  }

  if (origin && allowedOrigins.some((allowed) => origin.startsWith(allowed))) {
    res.setHeader('Access-Control-Allow-Origin', origin)
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-token')

  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const token = req.headers['x-api-token']
  if (token !== process.env['VITE_FRONTEND_API_TOKEN']) {
    return res.status(403).json({ error: 'Forbidden' })
  }

  const body = req.body as QueryRequest
  if (!body || typeof body.query !== 'string') {
    return res.status(400).json({ error: 'Invalid request: query is required' })
  }

  const apiKey = process.env['INDEXSUPPLY_API_KEY']
  if (!apiKey) {
    console.error('INDEXSUPPLY_API_KEY is not configured')
    return res
      .status(500)
      .json({ error: 'Server configuration error: API key not found' })
  }

  try {
    const endpoint = 'https://api.indexsupply.net/v2/query'
    const url = new URL(endpoint)
    url.searchParams.set('api-key', apiKey)

    const signatures =
      body.signatures && body.signatures.length > 0 ? body.signatures : ['']

    const chainId = tempoTestnet.id
    const chainCursor = `${chainId}-0`

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        {
          cursor: chainCursor,
          signatures,
          query: body.query.replace(/\s+/g, ' ').trim(),
        },
      ]),
    })

    let json: unknown
    try {
      json = await response.json()
    } catch {
      return res
        .status(502)
        .json({ error: 'Index Supply API returned invalid JSON' })
    }

    if (!response.ok) {
      const message =
        typeof json === 'object' &&
        json !== null &&
        'message' in json &&
        typeof (json as { message?: string }).message === 'string'
          ? (json as { message: string }).message
          : response.statusText

      return res
        .status(response.status)
        .json({ error: `Index Supply API error: ${message}` })
    }

    const data = json as QueryResponse[]
    const [result] = data

    if (!result) {
      return res
        .status(500)
        .json({ error: 'Index Supply returned an empty result set' })
    }

    return res.status(200).json(result)
  } catch (error) {
    console.error('Error querying Index Supply:', error)
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    })
  }
}
