import nacl from 'tweetnacl/nacl-fast'
import { filter, map } from 'rxjs/operators'
import { decodeBase64, decodeUTF8, encodeBase64, encodeUTF8 } from 'tweetnacl-util'
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

  /**
   *  Returns the name of this connector. Mainly used in did and link constructions.
   *
   * @returns {string} The string 'ephemeral'.
   */
  getName () {
    return 'ephemeral'
  }

  /**
   * Configures the connector. If this function is called, it will connect to an instance of EphemeralServer.
   * If not, it will use an in-memory backend.
   *
   * @param {string} serverEndpoint - EphemeralServer endpoint for http calls
   * @param {string} websocketEndpoint - EphemeralServer endpoint for websocket connections
   * @param {object} w3cwebsocket - W3C compatible WebSocket implementation. In the browser, this is window.WebSocket.
   * For node.js, the `websocket` npm package provides a compatible implementation.
   */
  configure (serverEndpoint, websocketEndpoint, w3cwebsocket) {
    this.ephemeralClient = new EphemeralClient(serverEndpoint, websocketEndpoint, w3cwebsocket)
  }

  /**
   * Looks up the corresponding did for a particular claim.
   *
   * This information is saved in the backing memory on calls to claim (either directly, or indirectly through import)
   *
   * @param {string} link - Link to the claim
   * @returns {Promise<string>} Did that made this claim
   */
  async getDidOfClaim (link) {
    let reference = BaseConnector.referenceFromLink(link)
    return this.didFromReference(await this.ephemeralClient.getPublicKey(reference))
  }

  /**
   * Returns a link to the last claim made by this did
   *
   * @param {string} did
   * @returns {Promise<string>} Link to the last claim made by this did
   */
  async getLatestClaim (did) {
    return this.linkFromReference(await this.ephemeralClient.getLatest(BaseConnector.referenceFromDid(did)))
  }

  /**
   * Generates a new ephemeral identity, backed by a keypair generated with tweetnacl.
   *
   * @returns {Promise<{privkey: string, did: string}>} ssid-object, containing both the did and the authentication mechanism.
   */
  async newIdentity () {
    let keypair = nacl.sign.keyPair()

    return { 'did': this.didFromReference(encodeBase64(keypair.publicKey)), 'privkey': encodeBase64(keypair.secretKey) }
  }

  /**
   * Expresses a claim
   *
   * The data will be serialized using a stable stringify that only depends on the actual data being claimed,
   * and not on the order of insertion of attributes.
   * If the exact claim has been made before, this will return the existing link, but not recreate the claim.
   *
   * @param {string} did - Identity that expresses the claim
   * @param {string} privkey - Base64 encoded authentication mechanism
   * @param {object} data - Arbitrary object that constitutes the data being claimed.
   * @param {object} [data.DISCIPL_ALLOW] - Special type of claim that manages ACL
   * @param {string} [data.DISCIPL_ALLOW.scope] - Single link. If not present, the scope is the whole channel
   * @param {string} [data.DISCIPL_ALLOW.did] - Did that is allowed access. If not present, everyone is allowed.
   * @returns {Promise<string>} link - Link to the produced claim
   */
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

  /**
   * Retrieve a claim by its link
   *
   * @param {string} link - Link to the claim
   * @param {string} did - Did that wants access
   * @param {string} privkey - Key of the did requesting access
   * @returns {Promise<{data: object, previous: string}>} Object containing the data of the claim and a link to the
   * claim before it.
   */
  async get (link, did = null, privkey = null) {
    let reference = BaseConnector.referenceFromLink(link)
    let pubkey = BaseConnector.referenceFromDid(did)

    let signature
    if (pubkey != null && privkey != null) {
      signature = encodeBase64(nacl.sign.detached(decodeBase64(reference), decodeBase64(privkey)))
    }

    let result = await this.ephemeralClient.get(reference, pubkey, signature)

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

  /**
   * Imports a claim that was exported from another ephemeral connector.
   *
   * This needs the signature on it, in the form of the link. The signature is verfied when using this method.
   *
   * @param {string} did - Did that originally made this claim
   * @param {string} link - Link to the claim, which contains the signature over the data
   * @param {object} data - Data in the original claim
   * @param {string} importerDid - Did that will automatically get access to imported claim
   * @returns {Promise<string>} - Link to the claim if successfully imported, null otherwise.
   */
  async import (did, link, data, importerDid = null) {
    let message = encodeBase64(decodeUTF8(stringify(data)))
    let claim = {
      'message': message,
      'signature': BaseConnector.referenceFromLink(link),
      'publicKey': BaseConnector.referenceFromDid(did)
    }

    if (importerDid != null) {
      claim['access'] = {
        'scope': link,
        'did': importerDid
      }
    }
    return this.linkFromReference(await this.ephemeralClient.claim(claim))
  }

  /**
   * Observe claims being made in the connector
   *
   * @param {string} did - Only observe claims from this did
   * @param {object} claimFilter - Only observe claims that contain this data. If a value is null, claims with the key will be observed.
   * @param {string} accessorDid - Did requesting access
   * @param {string} accessorPrivkey - Private key of did requesting access
   * @returns {Promise<Observable<{claim: {data: object, previous: string}, did: string}>>}
   */
  async observe (did, claimFilter = {}, accessorDid = null, accessorPrivkey = null) {
    let pubkey = BaseConnector.referenceFromDid(did)
    let accessorPubkey = BaseConnector.referenceFromDid(accessorDid)

    let signature = null
    if (accessorPubkey != null && accessorPrivkey != null) {
      let message = pubkey == null ? decodeUTF8('null') : decodeBase64(pubkey)
      signature = encodeBase64(nacl.sign.detached(message, decodeBase64(accessorPrivkey)))
    }

    let subject = this.ephemeralClient.observe(pubkey, accessorPubkey, signature)

    if (subject == null) {
      return null
    }

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
