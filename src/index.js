import nacl from 'tweetnacl/nacl-fast'
import axios from 'axios'
import { filter, map } from 'rxjs/operators'
import { WebSocketSubject } from 'rxjs/webSocket'
import { w3cwebsocket } from 'websocket'
import { encodeBase64, decodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util'
import { BaseConnector } from 'discipl-core-baseconnector'
import { EphemeralServer } from './server'

class EphemeralConnector extends BaseConnector {
  getName () {
    return 'ephemeral'
  }

  configure (serverEndpoint, websocketEndpoint) {
    this.serverEndpoint = serverEndpoint
    this.websocketEndpoint = websocketEndpoint
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
    let response = await axios.post(this.serverEndpoint + '/get', JSON.parse(encodeUTF8(decodeBase64(reference))))

    return response.data
  }

  async observe (ssid, claimFilter = {}) {
    let socket = new WebSocketSubject({ 'url': this.websocketEndpoint, 'WebSocketCtor': w3cwebsocket })

    socket.next(ssid.pubkey)

    let processedSocked = socket.pipe(filter(claim => {
      if (claimFilter != null) {
        for (let predicate of Object.keys(claimFilter)) {
          if (claim['data'][predicate] == null) {
            // Predicate not present in claim
            return false
          }

          if (claimFilter[predicate] != null && claimFilter[predicate] !== claim['data'][predicate]) {
            // Object is provided in filter, but does not match with actual claim
            return false
          }
        }
      }

      return ssid == null || claim.ssid.pubkey === ssid.pubkey
    })
    )
      .pipe(map(claim => {
        if (claim.previous != null) {
          claim.previous = encodeBase64(decodeUTF8(JSON.stringify({ 'claimId': claim.previous, 'publicKey': ssid.pubkey })))
        }
        return claim
      }))
    return processedSocked
  }
}

export default EphemeralConnector
export { EphemeralServer }
