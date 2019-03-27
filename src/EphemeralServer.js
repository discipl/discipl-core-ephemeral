import express from 'express'
import ws from 'ws'
import EphemeralStorage from './EphemeralStorage'
import stringify from 'json-stable-stringify'

/**
 * EphemeralServer provides a http/ws interface for the logic contained in the EphemeralStorage class
 */
class EphemeralServer {
  constructor (port) {
    this.port = port
    this.storage = new EphemeralStorage()
  }

  start () {
    const app = express()
    app.use(express.json())
    app.post('/claim', (req, res) => this.claim(req, res))
    app.post('/get', (req, res) => this.get(req, res))
    app.post('/getLatest', (req, res) => this.getLatest(req, res))
    app.post('/getPublicKey', (req, res) => this.getPublicKey(req, res))

    this.server = app.listen(this.port, () => console.log(`Ephemeral server listening on ${this.port}!`))

    let wss = new ws.Server({ 'port': this.port + 1 })
    wss.on('connection', (ws) => {
      ws.on('message', (message) => {
        let params = JSON.parse(message)
        let subject = this.storage.observe(params.scope, params.accessorPubkey, params.accessorSignature)

        let errorCallback = (error) => {
          if (error != null && !error.message.includes('WebSocket is not open')) {
            console.log('Error while sending ws message: ' + error)
          }
        }

        let observer = {
          'next': (value) => ws.send(stringify(value), {}, errorCallback)
        }

        subject.subscribe(observer)
      })
    })

    this.wss = wss
  }

  async claim (req, res) {
    // Protect against non-memory access injection
    console.log(req.body)
    if (req.body.access) {
      console.log("Removing access")
      delete req.body.access
    }
    let result = await this.storage.claim(req.body)
    res.send(stringify(result))
  }

  async get (req, res) {
    let result = await this.storage.get(req.body.claimId, req.body.accessorPubkey, req.body.accessorSignature)
    res.send(result)
  }

  async getLatest (req, res) {
    res.send(await this.storage.getLatest(req.body.publicKey))
  }

  async getPublicKey (req, res) {
    let result = await this.storage.getPublicKey(req.body.claimId)
    res.send(result)
  }

  close () {
    console.log('Stopping Ephemeral server')
    this.server.close()
    this.wss.close()
  }
}

export default EphemeralServer
