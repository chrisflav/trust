import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { NextFunction, Request, Response } from 'express'
import { pool } from './db'

/**
 * Sessions as a signed cookie.
 *
 * The only thing a session has to carry is which identity you are, so a signed
 * cookie does it without a session store or a dependency.  It is signed, not
 * encrypted: the identity id is not a secret, and tampering is what matters.
 */
const SECRET = process.env.SESSION_SECRET ?? ''
const COOKIE = 'trust_session'

export interface SessionUser {
  id: number
  login: string
}

function sign(value: string): string {
  return createHmac('sha256', SECRET).update(value).digest('base64url')
}

export function issueSession(response: Response, user: SessionUser): void {
  const payload = Buffer.from(JSON.stringify(user)).toString('base64url')
  const cookie = `${payload}.${sign(payload)}`
  response.cookie(COOKIE, cookie, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  })
}

export function readSession(request: Request): SessionUser | null {
  const raw = request.headers.cookie
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1)
  if (!raw) return null
  const dot = raw.lastIndexOf('.')
  if (dot < 0) return null
  const payload = raw.slice(0, dot)
  const provided = Buffer.from(raw.slice(dot + 1))
  const expected = Buffer.from(sign(payload))
  // Constant-time, so the comparison cannot be used to guess a valid signature.
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString()) as SessionUser
  } catch {
    return null
  }
}

export function requireUser(request: Request, response: Response, next: NextFunction): void {
  const user = readSession(request)
  if (!user) {
    response.status(401).json({ error: 'sign in with GitHub first' })
    return
  }
  ;(request as Request & { user: SessionUser }).user = user
  next()
}

export function currentUser(request: Request): SessionUser {
  return (request as Request & { user: SessionUser }).user
}

/** Short-lived anti-forgery state for the OAuth round trip. */
const pendingStates = new Map<string, number>()

export function newState(): string {
  const state = randomBytes(16).toString('hex')
  pendingStates.set(state, Date.now())
  for (const [key, at] of pendingStates) {
    if (Date.now() - at > 10 * 60 * 1000) pendingStates.delete(key)
  }
  return state
}

export function consumeState(state: string): boolean {
  return pendingStates.delete(state)
}

interface GitHubUser {
  id: number
  login: string
  avatar_url?: string
}

export async function exchangeCode(code: string): Promise<GitHubUser> {
  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  })
  const token = (await tokenResponse.json()) as { access_token?: string; error?: string }
  if (!token.access_token) throw new Error(token.error ?? 'GitHub did not return a token')
  const userResponse = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${token.access_token}`, Accept: 'application/vnd.github+json' },
  })
  if (!userResponse.ok) throw new Error(`GitHub user lookup failed: ${userResponse.status}`)
  return (await userResponse.json()) as GitHubUser
}

/**
 * The public keys GitHub itself publishes for an account.
 *
 * Used to mark a key `github` rather than `self`: it ties a fingerprint to an
 * account through a party that is not us, which is a materially stronger claim
 * than "someone pasted this here while signed in".
 */
export async function githubPublicKeys(login: string): Promise<string[]> {
  try {
    const response = await fetch(`https://api.github.com/users/${encodeURIComponent(login)}/gpg_keys`, {
      headers: { Accept: 'application/vnd.github+json' },
    })
    if (!response.ok) return []
    const keys = (await response.json()) as { raw_key?: string }[]
    return keys.map((key) => key.raw_key ?? '').filter((key) => key.length > 0)
  } catch {
    return []
  }
}

export async function upsertIdentity(user: GitHubUser): Promise<SessionUser> {
  const { rows } = await pool.query<{ id: string; login: string }>(
    `INSERT INTO identity (github_id, login, avatar_url)
     VALUES ($1, $2, $3)
     ON CONFLICT (github_id) DO UPDATE SET login = EXCLUDED.login, avatar_url = EXCLUDED.avatar_url
     RETURNING id, login`,
    [user.id, user.login, user.avatar_url ?? ''],
  )
  return { id: Number(rows[0].id), login: rows[0].login }
}
