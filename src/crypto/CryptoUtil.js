import forge from 'node-forge'
import stringify from 'json-stable-stringify'

class CryptoUtil {
  static objectToDigest (o) {
    const md = forge.md.sha256.create()
    md.update(stringify(o), 'utf8')
    return md
  }
}

export default CryptoUtil
