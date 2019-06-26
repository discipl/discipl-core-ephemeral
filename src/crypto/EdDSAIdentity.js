import forge from 'node-forge'
import CryptoUtil from './CryptoUtil'
const EC_PREFIX = 'ec:'

class EdDSAIdentity {
  constructor (reference = null, privkey = null) {
    if (reference == null) {
      let keypair = forge.pki.ed25519.generateKeyPair()

      let reference = EC_PREFIX + keypair.publicKey.toString('base64')

      this.keypair = keypair
      this.reference = reference
      this.ssid = {
        'privkey': keypair.privateKey,
        'metadata': {
        }
      }
    } else {
      this.keypair = {
        'publicKey': Buffer.from(reference.replace(EC_PREFIX, ''), 'base64'),
        'privateKey': privkey
      }
    }
  }

  sign (data) {
    let md = CryptoUtil.objectToDigest(data)

    let signature = forge.pki.ed25519.sign({
      'md': md,
      'privateKey': this.keypair.privateKey
    })

    return signature.toString('base64')
  }

  verify (data, signature) {
    return forge.pki.ed25519.verify({
      'md': CryptoUtil.objectToDigest(data),
      'signature': Buffer.from(signature, 'base64'),
      'publicKey': this.keypair.publicKey
    })
  }
}

export default EdDSAIdentity
export {
  EC_PREFIX
}
