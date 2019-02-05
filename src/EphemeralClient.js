import axios from 'axios'
import { WebSocketSubject } from 'rxjs/webSocket'
import { map } from 'rxjs/operators'

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

  async get (claimId) {
    let response = await axios.post(this.serverEndpoint + '/get', { 'claimId': claimId })
    return response.data
  }

  async getLatest (publicKey) {
    let response = await axios.post(this.serverEndpoint + '/getLatest', { 'publicKey': publicKey })

    return response.data
  }

  observe (publicKey = null) {
    let socket = new WebSocketSubject({ 'url': this.websocketEndpoint, 'WebSocketCtor': this.w3cwebsocket })

    if (publicKey != null) {
      socket.next(publicKey)
    } else {
      socket.next('GLOBAL')
    }

    return socket
  }
}

export default EphemeralClient
