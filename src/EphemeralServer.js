import express from 'express'
import ws from 'ws'
import EphemeralStorage from './EphemeralStorage'
import stringify from 'json-stable-stringify'
import forge from 'node-forge'
import * as log from 'loglevel'
import fs from 'fs'
import https from 'https'

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

    this.server = https.createServer({
      key: fs.readFileSync(this.privateKeyPath, { encoding: 'utf-8' }),
      cert: fs.readFileSync(this.certificatePath, { encoding: 'utf-8' })
    }, app).listen(this.port, null, 511, () => this.logger.info(`Secure ephemeral server listening on ${this.port}!`))

    const wss = new ws.Server({ server: this.server })
    wss.on('connection', (wsCon) => {
      wsCon.on('message', (nonce) => {
        this.websockets[JSON.parse(nonce)] = wsCon
      })
    })

    this.wss = wss
  }

  clean () {
    const now = new Date().getTime()
    for (const entry of Object.entries(this.timestamps)) {
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
      const result = await this.storage.claim(req.body)
      this.ping(req.body.publicKey)
      res.send(stringify(result))
    } catch (e) {
      this.logger.warn('Error while claiming', e)
      res.status(401).send(e)
    }
  }

  async get (req, res) {
    try {
      const result = await this.storage.get(req.body.claimId, req.body.accessorPubkey, req.body.accessorSignature)
      this.ping(req.body.accessorPubkey)
      this.ping(await this.storage.getPublicKey(req.body.claimId))
      res.send(stringify(result))
    } catch (e) {
      this.logger.warn('Error while getting', e)
      res.status(401).send(e)
    }
  }

  async getLatest (req, res) {
    res.send(stringify(await this.storage.getLatest(req.body.publicKey)))
    this.ping(req.body.accessorPubkey)
  }

  async getPublicKey (req, res) {
    const result = await this.storage.getPublicKey(req.body.claimId)
    this.ping(result)
    res.send(stringify(result))
  }

  async storeCert (req, res) {
    this.logger.debug('Received request for certificate with fingerpint', req.body.fingerprint, 'through server')
    await this.storage.storeCert(req.body.fingerprint, forge.pki.certificateFromPem(req.body.cert))
    this.ping(stringify(req.body.fingerprint))
    res.send({})
  }

  async getCert (req, res) {
    const result = await this.storage.getCertForFingerprint(req.body.fingerprint)
    this.ping(req.body.fingerprint)
    res.send(stringify(forge.pki.certificateToPem(result)))
  }

  async observe (req, res) {
    if (!req.body.nonce || !Object.keys(this.websockets).includes(req.body.nonce)) {
      res.sendStatus(404)
      return
    }

    const observeResult = await this.storage.observe(req.body.scope, req.body.accessorPubkey, req.body.accessorSignature)

    this.ping(req.body.accessorPubkey)
    this.ping(req.body.scope)

    const subject = observeResult[0]

    const errorCallback = (error) => {
      if (error != null && !error.message.includes('WebSocket is not open')) {
        this.logger.error('Error while sending ws message:', error)
      }
    }

    const wsCon = this.websockets[req.body.nonce]

    const observer = {
      next: (value) => wsCon.send(stringify(value), {}, errorCallback)
    }

    subject.subscribe(observer)

    res.send({})
  }

  close () {
    this.logger.info('Stopping Ephemeral Server')
    clearInterval(this.cleanInterval)
    this.wss.close()
    this.server.close()
  }
}

export default EphemeralServer
