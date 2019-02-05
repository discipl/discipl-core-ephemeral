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

    return encodeBase64(decodeUTF8(JSON.stringify({ 'claimId': response.data, 'publicKey': ssid.pubkey })))
  }

  async newSsid () {
    let keypair = nacl.sign.keyPair()

    return { 'pubkey': encodeBase64(keypair.publicKey), 'privkey': encodeBase64(keypair.secretKey) }
  }

  async claim (ssid, data) {
    let signedMessage = nacl.sign(decodeUTF8(JSON.stringify(data)), decodeBase64(ssid.privkey))

    let signedMessageString = encodeBase64(signedMessage)

    let response = await axios.post(this.serverEndpoint + '/claim', { 'signedMessage': signedMessageString, 'publicKey': ssid.pubkey })

    return encodeBase64(decodeUTF8(JSON.stringify({ 'claimId': response.data, 'publicKey': ssid.pubkey })))
  }

  async get (reference, ssid = null) {
    let request = JSON.parse(encodeUTF8(decodeBase64(reference)))
    let response = await axios.post(this.serverEndpoint + '/get', request)

    let result = response.data

    if (result.previous != null) {
      result.previous = encodeBase64(decodeUTF8(JSON.stringify({ 'claimId': result.previous, 'publicKey': request.publicKey })))
    }
    return result
  }

  async observe (ssid, claimFilter = {}) {
    let socket = new WebSocketSubject({ 'url': this.websocketEndpoint, 'WebSocketCtor': this.w3cwebsocket })
    if (ssid != null) {
      socket.next(ssid.pubkey)
    } else {
      socket.next('GLOBAL')
    }

    let processedSocked = socket.pipe(filter(claim => {
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
      .pipe(map(claim => {
        if (claim['claim'].previous != null) {
          claim['claim'].previous = encodeBase64(decodeUTF8(JSON.stringify({ 'claimId': claim['claim'].previous, 'publicKey': claim['ssid']['pubkey'] })))
        }
        return claim
      }))
    return processedSocked
  }
}

export default EphemeralConnector
