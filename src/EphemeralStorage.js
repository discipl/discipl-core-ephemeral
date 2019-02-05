import { decodeBase64, decodeUTF8, encodeBase64, encodeUTF8 } from 'tweetnacl-util'
import nacl from 'tweetnacl/nacl-fast'

class EphemeralStorage {
  constructor () {
    this.storage = {}
    this.globalObservers = []
  }

  claim (claim) {
    let verification = this.verifySignature(claim)

    if (verification !== true) {
      return null
    }

    let signature = claim.signature
    let message = claim.message

    let publicKey = claim.publicKey
    this.lazyInitStorage(publicKey)

    let nonce = encodeBase64(nacl.randomBytes(32))

    let claimId = encodeBase64(decodeUTF8(JSON.stringify({
      'nonce': nonce,
      'signature': signature,
      'publicKey': publicKey
    })))

    this.storage[publicKey]['claims'][claimId] = { 'data': message, 'signature': signature, 'previous': this.storage[publicKey]['last'] }
    this.storage[publicKey]['last'] = claimId

    for (let observer of this.storage[publicKey].observers.concat(this.globalObservers)) {
      let claim = this.storage[publicKey]['claims'][claimId]
      observer.next({ 'claim': claim, 'ssid': { 'pubkey': publicKey } })
    }

    return claimId
  }

  get (claimId) {
    let publicKey = JSON.parse(encodeUTF8(decodeBase64(claimId))).publicKey

    if (Object.keys(this.storage).includes(publicKey) && Object.keys(this.storage[publicKey]['claims']).includes(claimId)) {
      return this.storage[publicKey]['claims'][claimId]
    }
  }

  getLatest (publicKey) {
    if (Object.keys(this.storage).includes(publicKey) && this.storage[publicKey]['last'] != null) {
      return this.storage[publicKey]['last']
    }
  }

  observe (observer, publicKey = null) {
    if (publicKey !== null) {
      this.lazyInitStorage(publicKey)

      this.storage[publicKey].observers.push(observer)
    } else {
      this.globalObservers.push(observer)
    }
  }

  verifySignature (claim) {
    if (claim.message != null && claim.signature != null && claim.publicKey != null) {
      return nacl.sign.detached.verify(decodeBase64(claim.message), decodeBase64(claim.signature), decodeBase64(claim.publicKey))
    }
  }

  lazyInitStorage (publicKey) {
    if (!Object.keys(this.storage).includes(publicKey)) {
      this.storage[publicKey] = { 'claims': {}, 'last': null, 'observers': [] }
    }
  }
}

export default EphemeralStorage
