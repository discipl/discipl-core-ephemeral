import axios from 'axios'
import { WebSocketSubject } from 'rxjs/webSocket'
import forge from 'node-forge'
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

  async getCertForFingerprint (fingerprint) {
    let response = await axios.post(this.serverEndpoint + '/getCert', { 'fingerprint': fingerprint })

    return forge.pki.certificateFromPem(response.data)
  }

  async storeCert (fingerprint, cert) {
    let response = await axios.post(this.serverEndpoint + '/storeCert', { 'fingerprint': fingerprint, 'cert': forge.pki.certificateToPem(cert) })

    return response.data
  }

  async observe (publicKey = null, accessorPubkey = null, accessorSignature = null) {
    let nonce = forge.util.encode64(forge.random.getBytesSync(32))

    let socket = null

    /* The construct below is slightly convoluted. This is why:
       This function wants to return an observable. Since there is client-server communication involved, there is the
       potential for race conditions. In particular, since the websocket is only opened once the observable is
       subscribed to, the nonce is held in a local queue until subscription. At subscription time, the nonce is sent.
       The server has to actually receive it and put a listener in the right place. This means that the subscribe call
       itself does not guarantee that the listener is immediately in place. This is the function of the readyPromise.
       It gets confirmation from the server that the listener is in place, and is only resolved then.
    */
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
            // When the websocket is opened, the nonce is sent. The POST below sends the information to the server
            // that goes with this nonce, allowing it to start the actual observe.
            const MAX_TRIES = 10
            for (let i = 0; i < MAX_TRIES; i++) {
              await timeoutPromise(50)
              try {
                await axios.post(this.serverEndpoint + '/observe', {
                  'nonce': nonce,
                  'scope': publicKey,
                  'accessorPubkey': accessorPubkey,
                  'accessorSignature': accessorSignature
                }).then((r) => {
                  resolve()
                })
                return
              } catch (e) {
                // Purpose-ful no-op
              }
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
