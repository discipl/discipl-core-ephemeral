import express from 'express'
import ws from 'ws'
import EphemeralStorage from './EphemeralStorage'
import stringify from 'json-stable-stringify'
import forge from 'node-forge'

/**
 * EphemeralServer provides a http/ws interface for the logic contained in the EphemeralStorage class
 */
class EphemeralServer {
  constructor (port) {
    this.port = port
    this.storage = new EphemeralStorage()
    this.websockets = {}
  }

  start () {
    const app = express()
    app.use(express.json())
    app.post('/claim', (req, res) => this.claim(req, res))
    app.post('/get', (req, res) => this.get(req, res))
    app.post('/getLatest', (req, res) => this.getLatest(req, res))
    app.post('/getPublicKey', (req, res) => this.getPublicKey(req, res))
    app.post('/storeCert', (req, res) => this.storeCert(req, res))
    app.post('/getCert', (req, res) => this.getCert(req, res))
    app.post('/observe', (req, res) => this.observe(req, res))

    this.server = app.listen(this.port, () => console.log(`Ephemeral server listening on ${this.port}!`))

    let wss = new ws.Server({ 'port': this.port + 1 })
    wss.on('connection', (ws) => {
      ws.on('message', (nonce) => {
        this.websockets[JSON.parse(nonce)] = ws
      })
    })

    this.wss = wss
  }

  async claim (req, res) {
    // Protect against non-memory access injection
    if (req.body.access) {
      delete req.body.access
    }
    try {
      let result = await this.storage.claim(req.body)
      res.send(stringify(result))
    } catch (e) {
      res.status(401).send(e)
    }
  }

  async get (req, res) {
    try {
      let result = await this.storage.get(req.body.claimId, req.body.accessorPubkey, req.body.accessorSignature)
      res.send(result)
    } catch (e) {
      res.status(401).send(e)
    }
  }

  async getLatest (req, res) {
    res.send(await this.storage.getLatest(req.body.publicKey))
  }

  async getPublicKey (req, res) {
    let result = await this.storage.getPublicKey(req.body.claimId)
    res.send(result)
  }

  async storeCert (req, res) {
    await this.storage.storeCert(req.body.fingerprint, forge.pki.certificateFromPem(req.body.cert))
    res.sendStatus(200)
  }

  async getCert (req, res) {
    let result = await this.storage.getCertForFingerprint(req.body.fingerprint)
    res.send(forge.pki.certificateToPem(result))
  }

  async observe (req, res) {
    if (!req.body.nonce || !Object.keys(this.websockets).includes(req.body.nonce)) {
      res.sendStatus(404)
      return
    }

    let observeResult = await this.storage.observe(req.body.scope, req.body.accessorPubkey, req.body.accessorSignature)

    let subject = observeResult[0]

    let errorCallback = (error) => {
      if (error != null && !error.message.includes('WebSocket is not open')) {
        console.log('Error while sending ws message: ' + error)
      }
    }

    let ws = this.websockets[req.body.nonce]

    let observer = {
      'next': (value) => ws.send(stringify(value), {}, errorCallback)
    }

    subject.subscribe(observer)

    res.sendStatus(200)
  }

  close () {
    console.log('Stopping Ephemeral server')
    this.server.close()
    this.wss.close()
  }
}

export default EphemeralServer
