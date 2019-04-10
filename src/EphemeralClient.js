import axios from 'axios'
import nacl from 'tweetnacl/nacl-fast'
import { WebSocketSubject } from 'rxjs/webSocket'
import { decodeBase64, decodeUTF8, encodeBase64 } from 'tweetnacl-util'

/**
 * The EphemeralClient is responsible for communicating to the server. Its interface matches that
 * of the EphemeralStorage, such that one is a drop-in replacement for the other.
 */
class EphemeralClient {
  constructor (serverEndpoint, websocketEndpoint, w3cwebsocket) {
    this.serverEndpoint = serverEndpoint
    this.websocketEndpoint = websocketEndpoint
    this.w3cwebsocket = w3cwebsocket
  }

  async claim (claim) {
    let response = await axios.post(this.serverEndpoint + '/claim', claim)
    return response.data
  }

  async get (claimId, accessorPubkey, accessorSignature) {
    let response = await axios.post(this.serverEndpoint + '/get', { 'claimId': claimId, 'accessorPubkey': accessorPubkey, 'accessorSignature': accessorSignature })
    return response.data
  }

  async getLatest (publicKey) {
    let response = await axios.post(this.serverEndpoint + '/getLatest', { 'publicKey': publicKey })

    return response.data
  }

  async getPublicKey (claimId) {
    let response = await axios.post(this.serverEndpoint + '/getPublicKey', { 'claimId': claimId })

    return response.data
  }

  async observe (publicKey = null, accessorPubkey = null, accessorSignature = null) {
    // Verify the signature client side to prevent weird behaviour if the signature is invalid
    if (accessorPubkey != null && accessorSignature != null) {
      let message = publicKey == null ? decodeUTF8('null') : decodeBase64(publicKey)
      if (!nacl.sign.detached.verify(message, decodeBase64(accessorSignature), decodeBase64(accessorPubkey))) {
        throw new Error('Invalid authorization')
      }
    }

    let nonce = encodeBase64(nacl.randomBytes(32))

    let socket = null

    let readyPromise = new Promise((resolve, reject) => {
      const timeoutPromise = (timeoutMillis) => {
        return new Promise(function (resolve, reject) {
          setTimeout(() => resolve(), timeoutMillis)
        })
      }
      socket = new WebSocketSubject({
        'url': this.websocketEndpoint,
        'WebSocketCtor': this.w3cwebsocket,
        openObserver: {
          'next': async (e) => {
            const MAX_TRIES = 10
            for (let i = 0; i < MAX_TRIES; i++) {
              await timeoutPromise(50)

              await axios.post(this.serverEndpoint + '/observe', {
                'nonce': nonce,
                'scope': publicKey,
                'accessorPubkey': accessorPubkey,
                'accessorSignature': accessorSignature
              }).then((r) => {
                resolve()
              }).catch((e) => {
                // Purposeful no-op
              })
            }

            reject(new Error('Timed out'))
          }
        }
      })
    })

    socket.next(nonce)

    return [socket, readyPromise]
  }
}

export default EphemeralClient
