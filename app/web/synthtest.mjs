// Synthetic end-to-end test of the prover service WITHOUT a browser wallet:
// generate a throwaway key, sign a real SIWE message, hit /api/prove.
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { SiweMessage } from 'siwe'

const BASE = process.env.BASE || 'http://127.0.0.1:8090'
const account = privateKeyToAccount(generatePrivateKey())

const { nonce } = await (await fetch(BASE + '/api/nonce')).json()
console.log('challenge nonce:', nonce)

const message = new SiweMessage({
  domain: 'localhost:5173',
  address: account.address,
  statement: 'Prove ownership of this wallet for a proof-of-reserves attestation.',
  uri: 'http://localhost:5173',
  version: '1',
  chainId: 1,
  nonce,
}).prepareMessage()

const signature = await account.signMessage({ message })
console.log('signed by:', account.address)

const resp = await fetch(BASE + '/api/prove', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ message, signature, threshold: 1 }),
})
console.log('HTTP', resp.status)
console.log(await resp.text())
