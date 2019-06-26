import RSAIdentity from './RSAIdentity'
import EdDSAIdentity, { EC_PREFIX } from './EdDSAIdentity'
import { BaseConnector } from '@discipl/core-baseconnector'
import * as log from 'loglevel'

class IdentityFactory {
  constructor () {
    this.logger = log.getLogger('EphemeralConnector')
  }

  setConnector (ephemeralConnector) {
    this.ephemeralConnector = ephemeralConnector
    this.setClient(ephemeralConnector.ephemeralClient)
  }

  setClient (ephemeralClient) {
    this.ephemeralClient = ephemeralClient
  }

  async fromCert (cert, privkey) {
    const identity = new RSAIdentity(cert, privkey)
    await this.ephemeralClient.storeCert(identity.reference, identity.cert)

    identity.ssid.did = this.ephemeralConnector.didFromReference(identity.reference)

    return identity
  }

  async fromDid (did, privkey = null) {
    let reference = BaseConnector.referenceFromDid(did)

    return this.fromReference(reference, privkey)
  }

  async fromReference (reference, privkey = null) {
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
