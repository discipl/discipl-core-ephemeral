import express from 'express'
import nacl from 'tweetnacl/nacl-fast'
import { decodeBase64, encodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util'
import ws from 'ws'

class EphemeralServer {
  constructor (port) {
    const app = express()
    app.use(express.json())
    app.post('/claim', (req, res) => this.claim(req, res))
    app.post('/get', (req, res) => this.get(req, res))
    app.post('/getLatest', (req, res) => this.getLatest(req, res))

    this.server = app.listen(port, () => console.log(`Ephemeral server listening on ${port}!`))

    let wss = new ws.Server({ 'port': port + 1 })

    this.storage = {}
    this.globalObservers = []

    wss.on('connection', (ws) => {
      ws.on('message', (message) => {
        if (message === '"GLOBAL"') {
          this.observeGlobal(ws)
        } else {
          this.observe(ws, JSON.parse(message))
        }
      })
    })

    this.wss = wss
  }

  claim (req, res) {
    let verification = this.verifySignature(req.body)

    if (verification !== true) {
      res.send(JSON.stringify(null))
    }

    let signature = req.body.signature
    let message = req.body.message

    let publicKey = req.body.publicKey
    this.lazyInitStorage(publicKey)


    let nonce = encodeBase64(nacl.randomBytes(32))

    let claimId = encodeBase64(decodeUTF8(JSON.stringify({
      'nonce': nonce,
      'signature': signature,
      'publicKey': publicKey
    })))

    this.storage[publicKey]['claims'][claimId] = { 'data': message, 'signature': signature, 'previous': this.storage[publicKey]['last'] }
    this.storage[publicKey]['last'] = claimId

    for (let subscriberWs of this.storage[publicKey].subscribers.concat(this.globalObservers)) {
      let claim = this.storage[publicKey]['claims'][claimId]
      subscriberWs.send(JSON.stringify({ 'claim': claim, 'ssid': { 'pubkey': publicKey } }), {}, (error) => {
        if (error != null && !error.message.includes('WebSocket is not open')) {
          console.log('Error while sending ws message: ' + error)
        }
      })
    }

    res.send(JSON.stringify(claimId))
  }

  lazyInitStorage (publicKey) {
    if (!Object.keys(this.storage).includes(publicKey)) {
      this.storage[publicKey] = { 'claims': {}, 'last': null, 'subscribers': [] }
    }
  }

  get (req, res) {
    let claimId = req.body.claimId
    let publicKey = JSON.parse(encodeUTF8(decodeBase64(claimId))).publicKey


    if (Object.keys(this.storage).includes(publicKey) && Object.keys(this.storage[publicKey]['claims']).includes(claimId)) {
      res.send(this.storage[publicKey]['claims'][claimId])
    }
  }

  getLatest (req, res) {
    let publicKey = req.body.publicKey
    if (Object.keys(this.storage).includes(publicKey) && this.storage[publicKey]['last'] != null) {
      res.send(JSON.stringify(this.storage[publicKey]['last']))
    }
  }

  observe (ws, publicKey) {
    this.lazyInitStorage(publicKey)

    this.storage[publicKey].subscribers.push(ws)
  }

  observeGlobal (ws) {
    this.globalObservers.push(ws)
  }

  verifySignature (body) {
    if (body.message != null && body.signature != null && body.publicKey != null) {
      return nacl.sign.detached.verify(decodeBase64(body.message), decodeBase64(body.signature), decodeBase64(body.publicKey))
    }
  }

  close () {
    console.log('Stopping Ephemeral server')
    this.server.close()
    this.wss.close()
  }
}

export { EphemeralServer }
