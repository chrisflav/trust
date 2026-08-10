import { describe, expect, it } from 'vitest'
import { checkPeerUrl, isBlockedAddress, normalizeUrl } from './address'

describe('normalizeUrl', () => {
  it('lowercases the host and drops a trailing slash', () => {
    expect(normalizeUrl('https://Trust.Example.ORG/')).toBe('https://trust.example.org')
    expect(normalizeUrl('https://trust.example.org/node//')).toBe('https://trust.example.org/node')
  })

  it('keeps a non-default port, which is part of the identity', () => {
    expect(normalizeUrl('http://localhost:8090')).toBe('http://localhost:8090')
  })

  it('refuses credentials, queries and fragments', () => {
    expect(normalizeUrl('https://user:pw@a.example')).toMatchObject({ error: expect.any(String) })
    expect(normalizeUrl('https://a.example?x=1')).toMatchObject({ error: expect.any(String) })
    expect(normalizeUrl('https://a.example#f')).toMatchObject({ error: expect.any(String) })
  })

  it('refuses schemes that are not http(s)', () => {
    for (const url of ['file:///etc/passwd', 'ftp://a.example', 'gopher://a.example']) {
      expect(normalizeUrl(url)).toMatchObject({ error: expect.stringContaining('scheme') })
    }
    expect(normalizeUrl('not a url')).toMatchObject({ error: 'not a URL' })
  })
})

describe('isBlockedAddress', () => {
  it('blocks the ranges that are not on the public internet', () => {
    for (const address of [
      '0.0.0.0',
      '10.0.0.1',
      '127.0.0.1',
      '127.1.2.3',
      '169.254.169.254', // the cloud metadata service, the reason this exists
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '192.0.0.1',
      '100.64.0.1',
      '198.18.0.1',
      '224.0.0.1',
      '255.255.255.255',
    ]) {
      expect(isBlockedAddress(address), address).toBe(true)
    }
  })

  it('allows ordinary public addresses', () => {
    for (const address of ['8.8.8.8', '194.163.137.1', '172.32.0.1', '172.15.0.1', '99.64.0.1']) {
      expect(isBlockedAddress(address), address).toBe(false)
    }
  })

  it('blocks the IPv6 equivalents', () => {
    for (const address of [
      '::1',
      '::',
      '0:0:0:0:0:0:0:1',
      'fc00::1',
      'fd12:3456::1',
      'fe80::1',
      'ff02::1',
      '::ffff:127.0.0.1', // loopback wearing a v6 hat
      '::ffff:169.254.169.254',
    ]) {
      expect(isBlockedAddress(address), address).toBe(true)
    }
  })

  it('allows public IPv6', () => {
    for (const address of ['2001:4860:4860::8888', '2606:4700::1111', '::ffff:8.8.8.8']) {
      expect(isBlockedAddress(address), address).toBe(false)
    }
  })

  it('blocks anything that is not an address at all', () => {
    for (const value of ['', 'localhost', 'not-an-ip', '1.2.3', '1.2.3.4.5']) {
      expect(isBlockedAddress(value), value).toBe(true)
    }
  })
})

describe('checkPeerUrl', () => {
  const strict = { allowPrivate: false }
  const permissive = { allowPrivate: true }

  it('refuses plain http unless private addresses are allowed', async () => {
    expect(await checkPeerUrl('http://a.example', strict)).toMatchObject({
      error: expect.stringContaining('https'),
    })
    expect(await checkPeerUrl('http://a.example', permissive)).toMatchObject({
      url: 'http://a.example',
    })
  })

  it('refuses a literal private address without resolving anything', async () => {
    expect(await checkPeerUrl('https://127.0.0.1:8443', strict)).toMatchObject({
      error: expect.stringContaining('non-public'),
    })
    expect(await checkPeerUrl('https://[::1]:8443', strict)).toMatchObject({
      error: expect.stringContaining('non-public'),
    })
    expect(await checkPeerUrl('https://169.254.169.254', strict)).toMatchObject({
      error: expect.stringContaining('non-public'),
    })
  })

  it('refuses a name that resolves privately', async () => {
    // `localhost` is the one name every machine resolves the same way.
    expect(await checkPeerUrl('https://localhost', strict)).toMatchObject({
      error: expect.stringContaining('non-public'),
    })
  })

  it('lets local mode reach the machine it is running on', async () => {
    expect(await checkPeerUrl('http://127.0.0.1:8090', permissive)).toMatchObject({
      url: 'http://127.0.0.1:8090',
    })
  })
})
