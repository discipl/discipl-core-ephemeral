import express from 'express'
import ws from 'ws'
import EphemeralStorage from './EphemeralStorage'
import stringify from 'json-stable-stringify'
import forge from 'node-forge'
import * as log from 'loglevel'
import fs from 'fs'
import https from 'https'
import http from 'http'

/**
 * EphemeralServer provides a http/ws interface for the logic contained in the EphemeralStorage class
 */
class EphemeralServer {
  constructor (port, certificatePath = null, privateKeyPath = null, retentionTime = 24 * 3600) {
    this.port = port
    this.storage = new EphemeralStorage()
    this.websockets = {}
    this.timestamps = {}
    this.retentionTime = retentionTime
    this.certificatePath = certificatePath
    this.privateKeyPath = privateKeyPath

    this.logger = log.getLogger('EphemeralConnector')
    this.logger.setLevel('debug')

    // Set the interval to check at 1/10th of the retentionTime, such that we exceed retentionTime by at most 10%
    this.cleanInterval = setInterval(() => this.clean(), retentionTime * 100)
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

    if (this.certificatePath != null) {
      this.server = https.createServer({
        'key': fs.readFileSync(this.privateKeyPath, { encoding: 'utf-8' }),
        'cert': fs.readFileSync(this.certificatePath, { encoding: 'utf-8' })
      }, app).listen(this.port, null, 511, () => this.logger.info(`Secure phemeral server listening on ${this.port}!`))
    } else {
      this.server = http.createServer(app).listen(this.port, null, 511, () => this.logger.info(`Insecure ephemeral server listening on ${this.port}!`))
    }

    let wss = new ws.Server({ 'server': this.server })
    wss.on('connection', (ws) => {
      ws.on('message', (nonce) => {
        this.websockets[JSON.parse(nonce)] = ws
      })
    })

    this.wss = wss
  }

  clean () {
    let now = new Date().getTime()
    for (let entry of Object.entries(this.timestamps)) {
      if (now - entry[1].getTime() > this.retentionTime * 1000) {
        this.storage.deleteIdentity(entry[0])
      }
    }
  }

  ping (pubkey) {
    this.timestamps[pubkey] = new Date()
  }

  async claim (req, res) {
    // Protect against non-memory access injection
    if (req.body.access) {
      delete req.body.access
    }
    try {
      let result = await this.storage.claim(req.body)
      this.ping(req.body.publicKey)
      res.send(stringify(result))
    } catch (e) {
      res.status(401).send(e)
    }
  }

  async get (req, res) {
    try {
      let result = await this.storage.get(req.body.claimId, req.body.accessorPubkey, req.body.accessorSignature)
      this.ping(req.body.accessorPubkey)
      this.ping(await this.storage.getPublicKey(req.body.claimId))
      res.send(result)
    } catch (e) {
      res.status(401).send(e)
    }
  }

  async getLatest (req, res) {
    res.send(await this.storage.getLatest(req.body.publicKey))
    this.ping(req.body.accessorPubkey)
  }

  async getPublicKey (req, res) {
    let result = await this.storage.getPublicKey(req.body.claimId)
    this.ping(result)
    res.send(result)
  }

  async storeCert (req, res) {
    await this.storage.storeCert(req.body.fingerprint, forge.pki.certificateFromPem(req.body.cert))
    this.ping(req.body.fingerprint)
    res.sendStatus(200)
  }

  async getCert (req, res) {
    let result = await this.storage.getCertForFingerprint(req.body.fingerprint)
    this.ping(req.body.fingerprint)
    res.send(forge.pki.certificateToPem(result))
  }

  async observe (req, res) {
    if (!req.body.nonce || !Object.keys(this.websockets).includes(req.body.nonce)) {
      res.sendStatus(404)
      return
    }

    let observeResult = await this.storage.observe(req.body.scope, req.body.accessorPubkey, req.body.accessorSignature)

    this.ping(req.body.accessorPubkey)
    this.ping(req.body.scope)

    let subject = observeResult[0]

    let errorCallback = (error) => {
      if (error != null && !error.message.includes('WebSocket is not open')) {
        this.logger.error('Error while sending ws message:', error)
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
    this.logger.info('Stopping Ephemeral Server')
    clearInterval(this.cleanInterval)
    this.wss.close()
    this.server.close()
  }
}

export default EphemeralServer
