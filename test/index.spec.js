/* eslint-env mocha */
/* eslint-disable no-unused-expressions */

import { expect } from 'chai'
import sinon from 'sinon'
import axios from 'axios'
import EphemeralConnector from '../src/index'
import EphemeralServer from '../src/EphemeralServer'
import { take } from 'rxjs/operators'
import { w3cwebsocket } from 'websocket'

import { decodeBase64, encodeBase64 } from 'tweetnacl-util'

let ephemeralServer

const EPHEMERAL_ENDPOINT = 'http://localhost:3232'
const EPHEMERAL_WEBSOCKET_ENDPOINT = 'ws://localhost:3233'

const timeoutPromise = (timeoutMillis) => {
  return new Promise(function (resolve, reject) {
    setTimeout(() => resolve(), timeoutMillis)
  })
}

describe('discipl-ephemeral-connector', () => {
  describe('without a live server', () => {
    it('should present a name', async () => {
      let ephemeralConnector = new EphemeralConnector()
      expect(ephemeralConnector.getName()).to.equal('ephemeral')
    })

    it('should be able to generate an ssid', async () => {
      let ephemeralConnector = new EphemeralConnector()
      let ssid = await ephemeralConnector.newSsid()

      expect(ssid.pubkey).to.be.a('string')
      expect(ssid.pubkey.length).to.equal(44)
      expect(ssid.privkey).to.be.a('string')
      expect(ssid.privkey.length).to.equal(88)
    })

    it('should be able to detect wrong signatures when getting a claim', async () => {
      let ephemeralConnector = new EphemeralConnector()
      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)
      let axiosStub = sinon.stub(axios, 'post')
      axiosStub.onFirstCall().returns({ data: '10F4oC/OrXA5cti7AfIZNo11F4zJGg1Kt05UUF6gMjU=' })
      // Valid data would be eyJuZWVkIjoid2luZSJ9
      axiosStub.onSecondCall().returns({
        data:
          {
            data: 'eyJuZWVkIjoidGVhIn0=',
            signature:
              'E4QQuQk+7wL7sW+SLNeVjQtKqAZMFItnn2pPc4QWM01qH3TjiqhVyh2sQGSKiPil2wwRn+XKcltxmxGPG8T4CQ==',
            previous:
              'JplYGnYoheiLYxFfHgAzS/4w7Whd9+WEig9GPMOoJz5rsQs6npqAwbhw3cIsdyi50UniurIbuvbDBSZPFDqmAA=='
          }
      })

      let claim = await ephemeralConnector.get('eyJub25jZSI6InN2TGlWVmRJVmJodmJPTW04VURESEhiUXNUR1BHazMzMDBXQ3N1UW5ncTA9Iiwic2lnbmF0dXJlIjoiMzFrVVVVUnk3OXpqUy9kekNBeDN5RmxhNHhkNUp5cGFsbExTa2Z6cmVYazJaY21NdU10TFBwb2MvcC95UE1YdUptdm5DbnR1WVp5NjNpNDFrL0lKQkE9PSIsInB1YmxpY0tleSI6ImtTRGdtRi92d2cybE80NmdnTVV4blBLdHVlY3dPT2VYWUwxdnMyVVZVbFk9In0=')

      // Restore stub for other tests
      axiosStub.restore()

      expect(claim).to.equal(null)
    })
  })
  describe('with a backend', () => {
    before(() => {
      ephemeralServer = new EphemeralServer(3232)
      ephemeralServer.start()
    })

    after(() => {
      ephemeralServer.close()
    })

    let backends = [
      {
        'description': 'in memory',
        'createConnector': () => new EphemeralConnector()
      },
      {
        'description': 'in a server',
        'createConnector': () => {
          let ephemeralConnector = new EphemeralConnector()
          ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)
          return ephemeralConnector
        }
      }
    ]
    backends.forEach((backend) => {
      describe(backend.description, () => {
        it('should be able to claim something', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.be.a('string')

          let claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            'data': {
              'need': 'beer'
            },
            'previous': null
          })
        })

        it('should be able to claim something complicated', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': { 'for': 'speed' } })

          expect(claimLink).to.be.a('string')

          let claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            'data': {
              'need': {
                'for': 'speed'
              }
            },
            'previous': null
          })
        })

        it('should not be able to claim something with a wrong key', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let privkey = decodeBase64(ssid.privkey)
          privkey.reverse()
          ssid.privkey = encodeBase64(privkey)

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.equal(null)
        })

        it('should be able to obtain a reference to the last claim', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.be.a('string')

          let latestClaimLink = await ephemeralConnector.getLatestClaim(ssid)

          expect(claimLink).to.equal(latestClaimLink)
        })

        it('should be able to obtain the last claim', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let beerLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })
          let wineLink = await ephemeralConnector.claim(ssid, { 'need': 'wine' })

          let latestClaimLink = await ephemeralConnector.getLatestClaim(ssid)

          expect(wineLink).to.equal(latestClaimLink)

          let wineClaim = await ephemeralConnector.get(wineLink)

          expect(wineClaim).to.deep.equal({
            'data': {
              'need': 'wine'
            },
            'previous': beerLink
          })
        })

        it('should be able to get the ssid from a claim reference', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.be.a('string')

          let claimLinkSsid = await ephemeralConnector.getSsidOfClaim(claimLink)

          expect(claimLinkSsid.pubkey).to.be.a('string')
          expect(ssid.pubkey).to.equal(claimLinkSsid.pubkey)
        })

        it('should be able to claim something and listen to the connector', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()
          let observable = await ephemeralConnector.observe(ssid)
          let observer = observable.pipe(take(1)).toPromise()
          // TODO: Fix race conditions
          await timeoutPromise(50)

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.be.a('string')
          let observed = await observer

          expect(observed).to.deep.equal({
            'claim': {
              'data': {
                'need': 'beer'
              },
              'previous': null
            },
            'ssid': {
              'pubkey': ssid.pubkey
            }
          })
        })

        it('should be able to import a claim using the signature from reference and importing it under same claim id', async () => {
          let ephemeralConnector = new EphemeralConnector()
          let ssid = await ephemeralConnector.newSsid()
          let reference = await ephemeralConnector.claim(ssid, { 'need': 'beer' })
          let claim = await ephemeralConnector.get(reference)
          expect(claim.data).to.deep.equal({ 'need': 'beer' })
          ephemeralConnector = new EphemeralConnector()
          ssid.privkey = null
          let c = await ephemeralConnector.get(reference)
          expect(c).to.equal(null)
          let result = await ephemeralConnector.import(ssid, reference, claim.data)
          c = await ephemeralConnector.get(result)
          expect(c.data).to.deep.equal({ 'need': 'beer' })
          expect(reference).to.equal(result)
        })

        it('should be able to observe connector-wide', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()
          let observable = await ephemeralConnector.observe(null, { 'need': 'beer' })
          let observer = observable.pipe(take(1)).toPromise()
          // TODO: Fix race conditions
          await timeoutPromise(50)

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

          expect(claimLink).to.be.a('string')
          let observed = await observer

          expect(observed).to.deep.equal({
            'claim': {
              'data': {
                'need': 'beer'
              },
              'previous': null
            },
            'ssid': {
              'pubkey': ssid.pubkey
            }
          })
        })

        it('should be able to claim something and listen to the connector with a filter', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()
          let observable = await ephemeralConnector.observe(ssid, { 'need': 'wine' })
          let observer = observable.pipe(take(1)).toPromise()
          // TODO: Fix race conditions
          await timeoutPromise(50)

          let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })
          await ephemeralConnector.claim(ssid, { 'need': 'wine' })
          await ephemeralConnector.claim(ssid, { 'need': 'tea' })
          let observed = await observer

          expect(observed).to.deep.equal({
            'claim': {
              'data': {
                'need': 'wine'
              },
              'previous': claimLink
            },
            'ssid': {
              'pubkey': ssid.pubkey
            }
          })
        })

        it('should be able to claim something and listen to the connector with a filter on a predicate', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()
          let observable = await ephemeralConnector.observe(ssid, { 'need': null })
          let observer = observable.pipe(take(1)).toPromise()
          // TODO: Fix race conditions
          await timeoutPromise(50)

          let claimLink = await ephemeralConnector.claim(ssid, { 'desire': 'beer' })
          await ephemeralConnector.claim(ssid, { 'need': 'wine' })
          await ephemeralConnector.claim(ssid, { 'desire': 'tea' })
          let observed = await observer

          expect(observed).to.deep.equal({
            'claim': {
              'data': {
                'need': 'wine'
              },
              'previous': claimLink
            },
            'ssid': {
              'pubkey': ssid.pubkey
            }
          })
        })

        it('should be able to claim something and listen to the connector with a filter on a predicate without an ssid', async () => {
          let ephemeralConnector = backend.createConnector()

          let ssid = await ephemeralConnector.newSsid()
          let observable = await ephemeralConnector.observe(null, { 'need': null })
          let observer = observable.pipe(take(1)).toPromise()
          // TODO: Fix race conditions
          await timeoutPromise(50)

          let claimLink = await ephemeralConnector.claim(ssid, { 'desire': 'beer' })
          await ephemeralConnector.claim(ssid, { 'need': 'wine' })
          await ephemeralConnector.claim(ssid, { 'desire': 'tea' })
          let observed = await observer

          expect(observed).to.deep.equal({
            'claim': {
              'data': {
                'need': 'wine'
              },
              'previous': claimLink
            },
            'ssid': {
              'pubkey': ssid.pubkey
            }
          })
        })
      })
    })
  })
})
