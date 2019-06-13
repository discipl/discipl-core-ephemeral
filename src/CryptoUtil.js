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
        'signature': forge.util.decode64(signature),
        'publicKey': forge.util.createBuffer(cert.replace(EC_PREFIX, ''), 'base64')
      })
    }

    if (data != null && signature != null && cert != null) {
      const digest = this.objectToDigest(data)
      CryptoUtil.getLogger().trace('Verifying on digest', digest.digest().toHex())
      CryptoUtil.getLogger().trace('Verifying on signature', signature)
      return cert.publicKey.verify(digest.digest().bytes(), forge.util.encode64(signature))
    }
  }

  static sign (privateKeyPem, data) {
    if (typeof privateKeyPem === 'string') {
      let privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

      const md = CryptoUtil.objectToDigest(data)
      CryptoUtil.getLogger().trace('Signing on digest', md.digest().toHex())
      return forge.util.encode64(privateKey.sign(md))
    } else {
      let md = CryptoUtil.objectToDigest(data)
      console.log('private key', privateKeyPem)

      let signature = forge.pki.ed25519.sign({
        'md': md,
        'privateKey': privateKeyPem
      })

      return forge.util.decode64(signature)
    }
  }
}

export default CryptoUtil
