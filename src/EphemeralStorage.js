import { decodeBase64 } from 'tweetnacl-util'
import nacl from 'tweetnacl/nacl-fast'
import { Subject } from 'rxjs'

/**
 * EphemeralStorage is responsible for managing claims. It validates the signature when the claim comes in.
 */
class EphemeralStorage {
  constructor () {
    this.storage = {}
    this.claimOwners = {}
    this.globalObservers = []
  }

  async claim (claim) {
    let verification = this._verifySignature(claim)

    if (verification !== true) {
      return null
    }

    let signature = claim.signature
    let message = claim.message

    let publicKey = claim.publicKey
    this._lazyInitStorage(publicKey)

    let claimId = signature

    this.claimOwners[claimId] = publicKey
    this.storage[publicKey]['claims'][claimId] = { 'data': message, 'signature': signature, 'previous': this.storage[publicKey]['last'] }
    this.storage[publicKey]['last'] = claimId

    for (let observer of this.storage[publicKey].observers.concat(this.globalObservers)) {
      let claim = Object.assign({}, this.storage[publicKey]['claims'][claimId])
      observer.next({ 'claim': claim, 'pubkey': publicKey })
    }

    return claimId
  }

  async get (claimId) {
    let publicKey = this.claimOwners[claimId]

    if (Object.keys(this.storage).includes(publicKey) && Object.keys(this.storage[publicKey]['claims']).includes(claimId)) {
      return Object.assign({}, this.storage[publicKey]['claims'][claimId])
    }
  }

  async getLatest (publicKey) {
    if (Object.keys(this.storage).includes(publicKey) && this.storage[publicKey]['last'] != null) {
      return this.storage[publicKey]['last']
    }
  }

  async getPublicKey (claimId) {
    return this.claimOwners[claimId]
  }

  observe (publicKey = null) {
    let subject = new Subject()
    if (publicKey !== null) {
      this._lazyInitStorage(publicKey)

      this.storage[publicKey].observers.push(subject)
    } else {
      this.globalObservers.push(subject)
    }

    return subject
  }

  _verifySignature (claim) {
    if (claim.message != null && claim.signature != null && claim.publicKey != null) {
      return nacl.sign.detached.verify(decodeBase64(claim.message), decodeBase64(claim.signature), decodeBase64(claim.publicKey))
    }
  }

  _lazyInitStorage (publicKey) {
    if (!Object.keys(this.storage).includes(publicKey)) {
      this.storage[publicKey] = { 'claims': {}, 'last': null, 'observers': [] }
    }
  }
}

export default EphemeralStorage
