import { filter, flatMap } from 'rxjs/operators'
import { BaseConnector } from '@discipl/core-baseconnector'
import EphemeralClient from './EphemeralClient'
import EphemeralStorage from './EphemeralStorage'

import * as log from 'loglevel'
import IdentityFactory from './crypto/IdentityFactory'

import NodeCache from 'node-cache'

/**
 * The EphemeralConnector is a connector to be used in discipl-core. If unconfigured, it will use an in-memory
 * storage backend. If configured with endpoints, it will use the EphemeralServer as a backend.
 */
class EphemeralConnector extends BaseConnector {
  constructor(loglevel = 'warn') {
    super()
    this.ephemeralClient = new EphemeralStorage()
    this.logger = log.getLogger('EphemeralConnector')
    this.logger.setLevel(loglevel)
    this.identityFactory = new IdentityFactory()
    this.identityFactory.setConnector(this)
    this.myCache = new NodeCache()
  }

  /**
   *  Returns the name of this connector. Mainly used in did and link constructions.
   *
   * @returns {string} The string 'ephemeral'.
   */
  getName() {
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
   * @param {string} loglevel - Loglevel of the connector. Default at 'warn'. Change to 'info','debug' or 'trace' to
   * get more information
   */
  configure(serverEndpoint, websocketEndpoint, w3cwebsocket) {
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
  async getDidOfClaim(link) {
    let reference = BaseConnector.referenceFromLink(link)
    return this.didFromReference(await this.ephemeralClient.getPublicKey(reference))
  }

  /**
   * Returns a link to the last claim made by this did
   *
   * @param {string} did
   * @returns {Promise<string>} Link to the last claim made by this did
   */
  async getLatestClaim(did) {
    return this.linkFromReference(await this.ephemeralClient.getLatest(BaseConnector.referenceFromDid(did)))
  }

  /**
   * @typedef {Object} EphemeralSsid
   * @property {string} did - Did of the created identity
   * @property {string} privkey - PEM-encoded private key
   * @property {string} metadata.cert - PEM-encoded certificate of the identity
   */

  /**
   * Generates a new ephemeral identity, backed by a cert generated with forge.
   *
   * @returns {Promise<EphemeralSsid>} ssid-object, containing both the did and the authentication mechanism.
   */
  async newIdentity(options = {}) {
    this.logger.info('Creating new identity')
    if (options.cert) {
      let identity = await this.identityFactory.fromCert(options.cert, options.privkey)
      return identity.ssid
    }
    let identity = await this.identityFactory.newIdentity()
    return identity.ssid
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
  async claim(did, privkey, data) {
    log.info('Making a claim')
    // Sort the keys to get the same message for the same data

    let reference = BaseConnector.referenceFromDid(did)

    let identity = await this.identityFactory.fromDid(did, privkey)
    let signature = identity.sign(data)

    let claim = {
      'message': data,
      'signature': signature,
      'publicKey': reference
    }

    return this.linkFromReference(await this.ephemeralClient.claim(claim))
  }

  /**
   * @typedef {Object} ClaimInfo
   * @property {object} data - Data saved in the claim, can be an arbitrary object
   * @property {string|null} previous - Link to the previous claim, null if the claim is the first
   */

  /**
   * Retrieve a claim by its link
   *
   * @param {string} link - Link to the claim
   * @param {string} did - Did that wants access
   * @param {string} privkey - Key of the did requesting access
   * @returns {Promise<ClaimInfo>} Object containing the data of the claim and a link to the
   * claim before it.
   */
  async get(link, did = null, privkey = null) {
    try {
      let retrievedObjFromCache = this.myCache.get(link, true)
      return retrievedObjFromCache
    } catch (err) {
      let reference = BaseConnector.referenceFromLink(link)
      let pubkey = BaseConnector.referenceFromDid(did)

      let signature
      if (pubkey != null && privkey != null) {
        let identity = await this.identityFactory.fromDid(did, privkey)
        signature = identity.sign(reference)
      }

      let result = await this.ephemeralClient.get(reference, pubkey, signature)

      if (!(result) || !(result.data)) {
        this.logger.info('Could not find data for ', link)
        return null
      }

      let publicKeyFingerprint = await this.ephemeralClient.getPublicKey(reference)

      this.logger.debug('Retrieved fingerprint', publicKeyFingerprint)
      let identity = await this.identityFactory.fromReference(publicKeyFingerprint)
      identity.verify(result.data, reference)

      let retrievedObj = {
        'data': result.data,
        'previous': this.linkFromReference(result.previous)
      }
      this.myCache.set(link, retrievedObj)
      return retrievedObj
    }
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
  async import(did, link, data, importerDid = null) {
    let claim = {
      'message': data,
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
   * @typedef {object} ExtendedClaimInfo
   * @property {ClaimInfo} claim - The actual claim
   * @property {string} link - Link to this claim
   * @property {string} did - Did that made the claim
   */

  /**
   * Observe claims being made in the connector
   *
   * @param {string} did - Only observe claims from this did
   * @param {object} claimFilter - Only observe claims that contain this data. If a value is null, claims with the key will be observed.
   * @param {string} accessorDid - Did requesting access
   * @param {string} accessorPrivkey - Private key of did requesting access
   * @returns {Promise<{observable: Observable<ExtendedClaimInfo>, readyPromise: Promise<>}>} -
   * The observable can be subscribed to. The readyPromise signals that the observation has truly started.
   */
  async observe(did, claimFilter = {}, accessorDid = null, accessorPrivkey = null) {
    let pubkey = BaseConnector.referenceFromDid(did)
    let accessorPubkey = BaseConnector.referenceFromDid(accessorDid)

    let signature = null
    if (accessorPubkey != null && accessorPrivkey != null) {
      let message = pubkey == null ? 'null' : pubkey
      let identity = await this.identityFactory.fromDid(accessorDid, accessorPrivkey)
      signature = identity.sign(message)
    }

    let [subject, readyPromise] = await this.ephemeralClient.observe(pubkey, accessorPubkey, signature)

    // TODO: Performance optimization: Move the filter to the server to send less data over the websockets
    let processedSubject = subject.pipe(flatMap(async (claim) => {
      let identity = await this.identityFactory.fromReference(claim.pubkey)
      identity.verify(claim['claim'].data, claim['claim'].signature)

      if (claim['claim'].previous) {
        claim['claim'].previous = this.linkFromReference(claim['claim'].previous)
      }

      claim['link'] = this.linkFromReference(claim['claim'].signature)
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

    return { 'observable': processedSubject, 'readyPromise': readyPromise }
  }
}

export default EphemeralConnector
