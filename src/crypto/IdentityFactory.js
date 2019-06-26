import RSAIdentity from './RSAIdentity'
import EdDSAIdentity, { EC_PREFIX } from './EdDSAIdentity'
import { BaseConnector } from '@discipl/core-baseconnector'
import * as log from 'loglevel'

class IdentityFactory {
  constructor (ephemeralConnector) {
    this.ephemeralConnector = ephemeralConnector
    this.ephemeralClient = ephemeralConnector.ephemeralClient
    this.logger = log.getLogger('EphemeralConnector')
  }

  async fromCert (cert, privkey) {
    const identity = new RSAIdentity(cert, privkey)
    await this.ephemeralClient.storeCert(identity.reference, identity.cert)

    identity.ssid.did = this.ephemeralConnector.didFromReference(identity.reference)

    return identity
  }

  async fromDid (did, privkey) {
    let reference = BaseConnector.referenceFromDid(did)

    if (reference.startsWith(EC_PREFIX)) {
      return new EdDSAIdentity(reference, privkey)
    } else {
      // Reference starts with CRT_PREFIX
      let cert = await this.ephemeralClient.getCertForFingerprint(reference)
      this.logger.debug('Retrieved cert', cert)
      return new RSAIdentity(cert, privkey)
    }
  }

  newIdentity () {
    const identity = new EdDSAIdentity()
    identity.ssid.did = this.ephemeralConnector.didFromReference(identity.reference)
    return identity
  }
}

export default IdentityFactory
