import forge from 'node-forge'
import * as log from 'loglevel'
import CryptoUtil from './CryptoUtil'

const CRT_PREFIX = 'crt:'

class RSAIdentity {
  constructor (cert, privkey = null) {
    this.logger = log.getLogger('EphemeralConnector')
    const parsedCert = typeof cert === 'string' ? forge.pki.certificateFromPem(cert) : cert

    const fingerprint = CRT_PREFIX + forge.pki.getPublicKeyFingerprint(parsedCert.publicKey, {
      encoding: 'hex'
    })

    this.logger.info('Imported RSAIdentity')
    this.reference = fingerprint
    this.cert = parsedCert
    this.ssid = {
      privkey: privkey,
      metadata: {
        cert: forge.pki.certificateToPem(parsedCert)
      }
    }
  }

  sign (data) {
    const privateKey = forge.pki.privateKeyFromPem(this.ssid.privkey)

    const md = CryptoUtil.objectToDigest(data)
    return forge.util.encode64(privateKey.sign(md))
  }

  verify (data, signature) {
    const digest = CryptoUtil.objectToDigest(data)
    const verify = this.cert.publicKey.verify(digest.digest().bytes(), forge.util.decode64(signature, 'base64'))

    if (!verify) {
      throw new Error('Invalid signature')
    }

    return verify
  }
}

export default RSAIdentity
export {
  CRT_PREFIX
}
