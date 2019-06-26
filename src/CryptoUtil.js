import forge from 'node-forge'
import stringify from 'json-stable-stringify'
import * as log from 'loglevel'

const EC_PREFIX = 'ec:'

class CryptoUtil {
  static getLogger () {
    return log.getLogger('EphemeralConnector')
  }
  static objectToDigest (o) {
    const md = forge.md.sha256.create()
    md.update(stringify(o), 'utf8')
    return md
  }

  static verifySignature (data, signature, cert) {
    if (typeof cert === 'string' && cert.startsWith(EC_PREFIX)) {
      return forge.pki.ed25519.verify({
        'md': CryptoUtil.objectToDigest(data),
        'signature': Buffer.from(signature, 'base64'),
        'publicKey': Buffer.from(cert.replace(EC_PREFIX, ''), 'base64')
      })
    }

    if (data != null && signature != null && cert != null) {
      const digest = this.objectToDigest(data)
      CryptoUtil.getLogger().trace('Verifying on digest', digest.digest().toHex())
      CryptoUtil.getLogger().trace('Verifying on signature', signature)
      return cert.publicKey.verify(digest.digest().bytes(), forge.util.decode64(signature, 'base64'))
    }
  }
}

export default CryptoUtil
