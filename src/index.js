import nacl from 'tweetnacl/nacl-fast'
import axios from 'axios'
import { encodeBase64, decodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util'
import { BaseConnector } from 'discipl-core-baseconnector'
import { EphemeralServer } from './server'

class EphemeralConnector extends BaseConnector {
  getName () {
    return 'ephemeral'
  }

  configure (serverEndpoint) {
    this.serverEndpoint = serverEndpoint
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

  async subscribe (ssid) {
    throw new TypeError('Subscribe is not implemented')
  }
}

export default EphemeralConnector
export { EphemeralServer }
