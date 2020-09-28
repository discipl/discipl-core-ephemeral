import { Subject } from 'rxjs'
import { BaseConnector } from '@discipl/core-baseconnector'
import * as log from 'loglevel'
import IdentityFactory from './crypto/IdentityFactory'
import * as lodash from 'lodash'

/**
 * EphemeralStorage is responsible for managing claims. It validates the signature when the claim comes in.
 */
class EphemeralStorage {
  constructor () {
    this.storage = {}
    this.claimOwners = {}
    this.fingerprints = {}
    this.globalObservers = []
    this.logger = log.getLogger('EphemeralConnector')

    this.identityFactory = new IdentityFactory()
    this.identityFactory.setClient(this)
  }

  async claim (claim) {
    const claimCopy = lodash.cloneDeep(claim)
    const verification = await this._verifySignature(claimCopy)

    if (verification !== true) {
      this.logger.warn('Invalid signature on claim by pubkey', claimCopy.publicKey)
      return null
    }

    const signature = claimCopy.signature
    const message = claimCopy.message

    const publicKey = claimCopy.publicKey
    this._lazyInitStorage(publicKey)

    const claimId = signature

    if (Object.keys(this.storage[publicKey].claims).includes(claimId)) {
      this.logger.info('Claim with id ', claimId, ' already existed')
      return claimId
    }

    this.claimOwners[claimId] = publicKey
    this.storage[publicKey].claims[claimId] = { data: message, signature: signature, previous: this.storage[publicKey].last, access: [] }
    this.storage[publicKey].last = claimId

    if (Object.keys(message).includes(BaseConnector.ALLOW) || claimCopy.access) {
      const access = message[BaseConnector.ALLOW] || claimCopy.access
      let object = this.storage[publicKey]

      if (BaseConnector.isLink(access.scope) && this.claimOwners[BaseConnector.referenceFromLink(access.scope)] === publicKey) {
        object = this.storage[publicKey].claims[BaseConnector.referenceFromLink(access.scope)]
      }

      if (access.did == null) {
        object.access = true
      } else {
        if (object.access !== true) {
          if (BaseConnector.isDid(access.did)) {
            object.access.push(BaseConnector.referenceFromDid(access.did))
          }
        }
      }
    }

    for (const listener of this.storage[publicKey].observers.concat(this.globalObservers)) {
      const sourceClaim = this.storage[publicKey].claims[claimId]
      const claimForObserver = {
        data: sourceClaim.data,
        signature: sourceClaim.signature,
        previous: sourceClaim.previous
      }

      if (this._hasAccessTo(claimId, listener.owner)) {
        listener.subject.next({ claim: claimForObserver, pubkey: publicKey })
      }
    }

    return claimId
  }

  _hasAccessTo (claimId, pubkey) {
    const claimPublicKey = this.claimOwners[claimId]

    if (claimPublicKey === pubkey) {
      return true
    }

    if (claimPublicKey == null) {
      return false
    }

    for (const accessObject of [this.storage[claimPublicKey].access, this.storage[claimPublicKey].claims[claimId].access]) {
      if (accessObject === true) {
        return true
      } else {
        if (accessObject.includes(pubkey)) {
          return true
        }
      }
    }

    return false
  }

  async get (claimId, accessorPubkey, accessorSignature) {
    if (accessorPubkey != null && accessorSignature != null) {
      const identity = await this.identityFactory.fromReference(accessorPubkey)
      identity.verify(claimId, accessorSignature)
    }

    const publicKey = this.claimOwners[claimId]

    if (Object.keys(this.storage).includes(publicKey) && Object.keys(this.storage[publicKey].claims).includes(claimId)) {
      const sourceClaim = this.storage[publicKey].claims[claimId]
      const claim = {
        data: lodash.cloneDeep(sourceClaim.data),
        signature: sourceClaim.signature,
        previous: sourceClaim.previous
      }

      if (this._hasAccessTo(claimId, accessorPubkey)) {
        return claim
      } else {
        this.logger.warn('Entity with fingerprint', accessorPubkey, 'tried to access', claimId, 'and failed')
      }
    }
  }

  async getLatest (publicKey) {
    if (Object.keys(this.storage).includes(publicKey) && this.storage[publicKey].last != null) {
      return this.storage[publicKey].last
    }
  }

  async getPublicKey (claimId) {
    return this.claimOwners[claimId]
  }

  async storeCert (reference, cert) {
    this.logger.debug('Storing', reference, 'with', cert)
    this.fingerprints[reference] = cert
  }

  async getCertForFingerprint (fingerprint) {
    this.logger.debug('Requesting cert for fingerprint', fingerprint)
    return this.fingerprints[fingerprint]
  }

  async observe (publicKey = null, accessorPubkey = null, accessorSignature = null) {
    if (accessorPubkey != null && accessorSignature != null) {
      const message = publicKey == null ? 'null' : publicKey

      const identity = await this.identityFactory.fromReference(accessorPubkey)
      identity.verify(message, accessorSignature)
    }

    const subject = new Subject()
    const listener = {
      subject: subject,
      owner: accessorPubkey
    }
    if (publicKey !== null) {
      this._lazyInitStorage(publicKey)

      this.storage[publicKey].observers.push(listener)
    } else {
      this.globalObservers.push(listener)
    }

    return [subject, Promise.resolve()]
  }

  async _verifySignature (claim) {
    const identity = await this.identityFactory.fromReference(claim.publicKey)
    return identity.verify(claim.message, claim.signature)
  }

  deleteIdentity (fingerprint) {
    this.logger.info('Deleting information related to fingerprint', fingerprint)
    delete this.storage[fingerprint]

    for (const claimIdOwner of Object.entries(this.claimOwners)) {
      this.logger.debug('Checking if ', claimIdOwner, 'is owned by', fingerprint)
      if (claimIdOwner[1] === fingerprint) {
        this.logger.debug('Deleting claimOwner entry for claimId', claimIdOwner[0])
        delete this.claimOwners[claimIdOwner[0]]
      }
    }

    console.log('Deleting fingerprint', fingerprint)
    delete this.fingerprints[fingerprint]

    // Iterate backwards to prevent issues with modifying while looping
    for (let i = this.globalObservers.length - 1; i >= 0; i--) {
      if (this.globalObservers[i].owner === fingerprint) {
        this.globalObservers.splice(i, 1)
      }
    }

    // Purposefully skip deleting the specific listeners, because iterating to them would take quite a lot of
    // time and they will get deleted when the key being listened to is no longer used.
  }

  _lazyInitStorage (publicKey) {
    if (!Object.keys(this.storage).includes(publicKey)) {
      this.storage[publicKey] = { claims: {}, last: null, observers: [], access: [] }
    }
  }
}

export default EphemeralStorage
