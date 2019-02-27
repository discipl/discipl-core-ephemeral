import nacl from 'tweetnacl/nacl-fast'
import { filter, map } from 'rxjs/operators'
import { encodeBase64, decodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util'
import { BaseConnector } from '@discipl/core-baseconnector'
import EphemeralClient from './EphemeralClient'
import EphemeralStorage from './EphemeralStorage'
import stringify from 'json-stable-stringify'

/**
 * The EphemeralConnector is a connector to be used in discipl-core. If unconfigured, it will use an in-memory
 * storage backend. If configured with endpoints, it will use the EphemeralServer as a backend.
 */
class EphemeralConnector extends BaseConnector {
  constructor () {
    super()
    this.ephemeralClient = new EphemeralStorage()
  }

  getName () {
    return 'ephemeral'
  }

  configure (serverEndpoint, websocketEndpoint, w3cwebsocket) {
    this.ephemeralClient = new EphemeralClient(serverEndpoint, websocketEndpoint, w3cwebsocket)
  }

  async getDidOfClaim (link) {
    let reference = BaseConnector.referenceFromLink(link)
    return this.didFromReference(await this.ephemeralClient.getPublicKey(reference))
  }

  async getLatestClaim (did) {
    return this.linkFromReference(await this.ephemeralClient.getLatest(BaseConnector.referenceFromDid(did)))
  }

  async newIdentity () {
    let keypair = nacl.sign.keyPair()

    return { 'did': this.didFromReference(encodeBase64(keypair.publicKey)), 'privkey': encodeBase64(keypair.secretKey) }
  }

  async claim (did, privkey, data) {
    // Sort the keys to get the same message for the same data
    let message = decodeUTF8(stringify(data))
    let signature = nacl.sign.detached(message, decodeBase64(privkey))

    let claim = {
      'message': encodeBase64(message),
      'signature': encodeBase64(signature),
      'publicKey': BaseConnector.referenceFromDid(did)
    }

    return this.linkFromReference(await this.ephemeralClient.claim(claim))
  }

  async get (link, ssid = null) {
    let reference = BaseConnector.referenceFromLink(link)
    let result = await this.ephemeralClient.get(reference)

    if (!(result) || !(result.data)) {
      return null
    }

    let publicKey = await this.ephemeralClient.getPublicKey(reference)

    let data = this._verifySignature(result.data, reference, publicKey)

    if (data == null) {
      return null
    }

    return {
      'data': data,
      'previous': this.linkFromReference(result.previous)
    }
  }

  _verifySignature (data, signature, publicKey) {
    if (data != null) {
      let decodedData = decodeBase64(data)
      if (nacl.sign.detached.verify(decodedData, decodeBase64(signature), decodeBase64(publicKey))) {
        return JSON.parse(encodeUTF8(decodedData))
      }
    }

    return null
  }

  async import (did, link, data) {
    let message = encodeBase64(decodeUTF8(stringify(data)))
    let claim = {
      'message': message,
      'signature': BaseConnector.referenceFromLink(link),
      'publicKey': BaseConnector.referenceFromDid(did)
    }
    return this.linkFromReference(await this.ephemeralClient.claim(claim))
  }

  async observe (did, claimFilter = {}) {
    let pubkey = did == null ? null : BaseConnector.referenceFromDid(did)
    let subject = this.ephemeralClient.observe(pubkey)

    // TODO: Performance optimization: Move the filter to the server to send less data over the websockets
    let processedSubject = subject.pipe(map(claim => {
      claim['claim'].data = this._verifySignature(claim['claim'].data, claim['claim'].signature, claim.pubkey)
      if (claim['claim'].previous) {
        claim['claim'].previous = this.linkFromReference(claim['claim'].previous)
      }

      delete claim['claim'].signature
      claim['did'] = this.didFromReference(claim['pubkey'])
      delete claim['pubkey']
      return claim
    })).pipe(filter(claim => {
      if (claimFilter != null) {
        for (let predicate of Object.keys(claimFilter)) {
          if (claim['claim']['data'][predicate] == null) {
            // Predicate not present in claim
            return false
          }

          if (claimFilter[predicate] != null && claimFilter[predicate] !== claim['claim']['data'][predicate]) {
            // Object is provided in filter, but does not match with actual claim
            return false
          }
        }
      }

      return did == null || claim.did === did
    })
    )

    return processedSubject
  }
}

export default EphemeralConnector
