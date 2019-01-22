import express from 'express'
import nacl from 'tweetnacl/nacl-fast'
import { decodeBase64, encodeBase64, encodeUTF8 } from 'tweetnacl-util'
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
    let message = this.getMessageFromBody(req.body)

    if (message != null) {
      let publicKey = req.body.publicKey
      this.lazyInitStorage(publicKey)

      let claimId = encodeBase64(nacl.randomBytes(32))

      this.storage[publicKey]['claims'][claimId] = { 'data': message, 'previous': this.storage[publicKey]['last'] }

      this.storage[publicKey]['last'] = claimId
      res.send(JSON.stringify(claimId))

      for (let subscriberWs of this.storage[publicKey].subscribers.concat(this.globalObservers)) {
        let claim = this.storage[publicKey]['claims'][claimId]
        subscriberWs.send(JSON.stringify({ 'claim': claim, 'ssid': { 'pubkey': publicKey } }), {}, (error) => {
          if (error != null && !error.message.includes('WebSocket is not open')) {
            console.log('Error while sending ws message: ' + error)
          }
        })
      }
    }
  }

  lazyInitStorage (publicKey) {
    if (!Object.keys(this.storage).includes(publicKey)) {
      this.storage[publicKey] = { 'claims': {}, 'last': null, 'subscribers': [] }
    }
  }

  get (req, res) {
    let publicKey = req.body.publicKey
    let claimId = req.body.claimId
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

  getMessageFromBody (body) {
    if (body.signedMessage != null && body.publicKey != null) {
      return JSON.parse(encodeUTF8(nacl.sign.open(decodeBase64(body.signedMessage), decodeBase64(body.publicKey))))
    }
  }

  close () {
    console.log('Stopping Ephemeral server')
    this.server.close()
    this.wss.close()
  }
}

export { EphemeralServer }
