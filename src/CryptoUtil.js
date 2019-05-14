import forge from 'node-forge'
import stringify from 'json-stable-stringify'

class CryptoUtil {
  static objectToDigest (o) {
    const md = forge.md.sha256.create()
    md.update(stringify(o), 'utf8')
    return md
  }

  static verifySignature (data, signature, cert) {
    if (data != null && signature != null && cert != null) {
      const digest = this.objectToDigest(data)

      return cert.publicKey.verify(digest, forge.util.decode64(signature))
    }
  }

  static sign (privateKeyPem, data) {
    let privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

    const md = CryptoUtil.objectToDigest(data)

    return forge.util.encode64(privateKey.sign(md))
  }
}

export default CryptoUtil
