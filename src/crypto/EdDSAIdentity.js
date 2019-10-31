import forge from 'node-forge'
import CryptoUtil from './CryptoUtil'
const EC_PREFIX = 'ec:'

class EdDSAIdentity {
  constructor (reference = null, privkey = null) {
    if (reference == null) {
      const keypair = forge.pki.ed25519.generateKeyPair()

      this.keypair = keypair
      this.reference = EC_PREFIX + keypair.publicKey.toString('base64')
      this.ssid = {
        privkey: keypair.privateKey,
        metadata: {
        }
      }
    } else {
      this.keypair = {
        publicKey: Buffer.from(reference.replace(EC_PREFIX, ''), 'base64'),
        privateKey: privkey
      }
    }
  }

  sign (data) {
    const md = CryptoUtil.objectToDigest(data)

    const signature = forge.pki.ed25519.sign({
      md: md,
      privateKey: this.keypair.privateKey
    })

    return signature.toString('base64')
  }

  verify (data, signature) {
    const verify = forge.pki.ed25519.verify({
      md: CryptoUtil.objectToDigest(data),
      signature: Buffer.from(signature, 'base64'),
      publicKey: this.keypair.publicKey
    })

    if (!verify) {
      throw new Error('Invalid signature')
    }

    return verify
  }
}

export default EdDSAIdentity
export {
  EC_PREFIX
}
