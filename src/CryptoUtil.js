import forge from 'node-forge'
import stringify from 'json-stable-stringify'
import * as log from 'loglevel'

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
    if (data != null && signature != null && cert != null) {
      const digest = this.objectToDigest(data)
      CryptoUtil.getLogger().trace('Verifying on digest', digest.digest().toHex())
      CryptoUtil.getLogger().trace('Verifying on signature', signature)
      return cert.publicKey.verify(digest.digest().bytes(), forge.util.decode64(signature))
    }
  }

  static sign (privateKeyPem, data) {
    let privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

    const md = CryptoUtil.objectToDigest(data)
    CryptoUtil.getLogger().trace('Signing on digest', md.digest().toHex())
    return forge.util.encode64(privateKey.sign(md))
  }
}

export default CryptoUtil
