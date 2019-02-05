import nacl from 'tweetnacl/nacl-fast'
import axios from 'axios'
import { filter, map } from 'rxjs/operators'
import { WebSocketSubject } from 'rxjs/webSocket'
import { encodeBase64, decodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util'
import { BaseConnector } from 'discipl-core-baseconnector'

class EphemeralConnector extends BaseConnector {
  getName () {
    return 'ephemeral'
  }

  configure (serverEndpoint, websocketEndpoint, w3cwebsocket) {
    this.serverEndpoint = serverEndpoint
    this.websocketEndpoint = websocketEndpoint
    this.w3cwebsocket = w3cwebsocket
  }

  async getSsidOfClaim (reference) {
    return { 'pubkey': JSON.parse(encodeUTF8(decodeBase64(reference))).publicKey }
  }

  async getLatestClaim (ssid) {
    let response = await axios.post(this.serverEndpoint + '/getLatest', { 'publicKey': ssid.pubkey })

    return response.data
  }

  async newSsid () {
    let keypair = nacl.sign.keyPair()

    return { 'pubkey': encodeBase64(keypair.publicKey), 'privkey': encodeBase64(keypair.secretKey) }
  }

  async claim (ssid, data) {
    let message = decodeUTF8(JSON.stringify(data))
    let signature = nacl.sign.detached(message, decodeBase64(ssid.privkey))

    let claim = {
      'message': encodeBase64(message),
      'signature': encodeBase64(signature),
      'publicKey': ssid.pubkey
    }

    let response = await axios.post(this.serverEndpoint + '/claim', claim)

    return response.data
  }

  async get (reference, ssid = null) {
    let response = await axios.post(this.serverEndpoint + '/get', { 'claimId': reference })

    let splitReference = JSON.parse(encodeUTF8(decodeBase64(reference)))
    let result = response.data

    result.data = this._verifySignature(result.data, splitReference.signature, splitReference.publicKey)

    return result
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

  async observe (ssid, claimFilter = {}) {
    let socket = new WebSocketSubject({ 'url': this.websocketEndpoint, 'WebSocketCtor': this.w3cwebsocket })
    if (ssid != null) {
      socket.next(ssid.pubkey)
    } else {
      socket.next('GLOBAL')
    }

    let processedSocked = socket.pipe(map(claim => {
      claim['claim'].data = this._verifySignature(claim['claim'].data, claim['claim'].signature, claim.ssid.pubkey)
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

      return ssid == null || claim.ssid.pubkey === ssid.pubkey
    })
    )

    return processedSocked
  }
}

export default EphemeralConnector
