import express from 'express'
import nacl from 'tweetnacl/nacl-fast'
import { decodeBase64, encodeBase64, encodeUTF8 } from 'tweetnacl-util'

class EphemeralServer {
  constructor (port) {
    const app = express()
    app.use(express.json())
    app.post('/claim', (req, res) => this.claim(req, res))
    app.post('/get', (req, res) => this.get(req, res))
    app.post('/getLatest', (req, res) => this.getLatest(req, res))

    this.server = app.listen(port, () => console.log(`Ephemeral server listening on ${port}!`))

    this.storage = {}
  }

  claim (req, res) {
    let message = this.getMessageFromBody(req.body)

    if (message != null) {
      let publicKey = req.body.publicKey
      if (!Object.keys(this.storage).includes(publicKey)) {
        this.storage[publicKey] = { 'claims': {}, 'last': null }
      }

      let claimId = encodeBase64(nacl.randomBytes(32))

      this.storage[publicKey]['claims'][claimId] = { 'data': message, 'previous': this.storage[publicKey]['last'] }

      this.storage[publicKey]['last'] = claimId
      res.send(JSON.stringify(claimId))
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

  getMessageFromBody (body) {
    if (body.signedMessage != null && body.publicKey != null) {
      return JSON.parse(encodeUTF8(nacl.sign.open(decodeBase64(body.signedMessage), decodeBase64(body.publicKey))))
    }
  }

  close () {
    this.server.close()
  }
}

export { EphemeralServer }
