/* eslint-env mocha */
/* eslint-disable no-unused-expressions */

import { expect } from 'chai'
import sinon from 'sinon'
import axios from 'axios'
import EphemeralConnector, { EphemeralServer } from '../src/index'
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
      // Valid data would be eyJuZWVkIjoid2luZSJ9
      axiosStub.returns({
        data:
          {
            data: 'eyJuZWVkIjoiYmVlciJ9',
            signature:
              '31kUUURy79zjS/dzCAx3yFla4xd5JypallLSkfzreXk2ZcmMuMtLPpoc/p/yPMXuJmvnCntuYZy63i41k/IJBA==',
            previous:
              'eyJub25jZSI6IjZUWDYzWFlSMHVnU3JJOEN5VzU4SktaRW1YNmVmV3l2bi90UDkzT0lRaUE9Iiwic2lnbmF0dXJlIjoic1F3T0Y0SndOMndBVVBZZVFsRmRDTFJFc1d5WUdSY0JiQkxGbXhYUE5aOU82bzBwWmZ2bTA5NVNnTk5YeGN4N0k4RGpmaG9zNWxoMklzcEJpc3hFREE9PSIsInB1YmxpY0tleSI6ImtTRGdtRi92d2cybE80NmdnTVV4blBLdHVlY3dPT2VYWUwxdnMyVVZVbFk9In0='
          }
      })

      let claim = await ephemeralConnector.get('eyJub25jZSI6InN2TGlWVmRJVmJodmJPTW04VURESEhiUXNUR1BHazMzMDBXQ3N1UW5ncTA9Iiwic2lnbmF0dXJlIjoiMzFrVVVVUnk3OXpqUy9kekNBeDN5RmxhNHhkNUp5cGFsbExTa2Z6cmVYazJaY21NdU10TFBwb2MvcC95UE1YdUptdm5DbnR1WVp5NjNpNDFrL0lKQkE9PSIsInB1YmxpY0tleSI6ImtTRGdtRi92d2cybE80NmdnTVV4blBLdHVlY3dPT2VYWUwxdnMyVVZVbFk9In0=')

      // Restore stub for other tests
      axiosStub.restore()

      expect(claim).to.equal(null)
    })
  })
  describe('with a live server', () => {
    before(() => {
      ephemeralServer = new EphemeralServer(3232)
      ephemeralServer.start()
    })

    after(() => {
      ephemeralServer.close()
    })

    it('should be able to claim something', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

      expect(claimLink).to.be.a('string')

      let claim = await ephemeralConnector.get(claimLink)

      expect(claim.data).to.deep.equal({ 'need': 'beer' })
      expect(claim.previous).to.equal(null)
      expect(claim.signature).to.be.a('string')
    })

    it('should not be able to claim something with a wrong key', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()

      let privkey = decodeBase64(ssid.privkey)
      privkey.reverse()
      ssid.privkey = encodeBase64(privkey)

      let errorMessage
      try {
        await ephemeralConnector.claim(ssid, { 'need': 'beer' })
      } catch (e) {
        errorMessage = e.message
      }

      expect(errorMessage).to.equal('Request failed with status code 401')
    })

    it('should be able to obtain a reference to the last claim', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

      expect(claimLink).to.be.a('string')

      let latestClaimLink = await ephemeralConnector.getLatestClaim(ssid)

      expect(claimLink).to.equal(latestClaimLink)
    })

    it('should be able to obtain the last claim', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()

      let beerLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })
      let wineLink = await ephemeralConnector.claim(ssid, { 'need': 'wine' })

      let latestClaimLink = await ephemeralConnector.getLatestClaim(ssid)

      expect(wineLink).to.equal(latestClaimLink)

      let wineClaim = await ephemeralConnector.get(wineLink)

      expect(wineClaim.data).to.deep.equal({ 'need': 'wine' })
      expect(wineClaim.previous).to.equal(beerLink)
      expect(wineClaim.signature).to.be.a('string')
    })

    it('should be able to get the ssid from a claim reference', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

      expect(claimLink).to.be.a('string')

      let claimLinkSsid = await ephemeralConnector.getSsidOfClaim(claimLink)

      expect(claimLinkSsid.pubkey).to.be.a('string')
      expect(ssid.pubkey).to.equal(claimLinkSsid.pubkey)
    })

    it('should be able to claim something and listen to the connector', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()
      let observable = await ephemeralConnector.observe(ssid)
      let observer = observable.pipe(take(1)).toPromise()
      // TODO: Fix race conditions
      await timeoutPromise(50)

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

      expect(claimLink).to.be.a('string')
      let observed = await observer

      expect(observed.claim.data).to.deep.equal({ 'need': 'beer' })
      expect(observed.claim.previous).to.equal(null)
      expect(observed.claim.signature).to.be.a('string')
      expect(observed.ssid).to.deep.equal({ 'pubkey': ssid.pubkey })
    })

    it('should be able to observe connector-wide', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()
      let observable = await ephemeralConnector.observe(null, { 'need': 'beer' })
      let observer = observable.pipe(take(1)).toPromise()
      // TODO: Fix race conditions
      await timeoutPromise(50)

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

      expect(claimLink).to.be.a('string')
      let observed = await observer

      expect(observed.claim.data).to.deep.equal({ 'need': 'beer' })
      expect(observed.claim.previous).to.equal(null)
      expect(observed.claim.signature).to.be.a('string')
      expect(observed.ssid).to.deep.equal({ 'pubkey': ssid.pubkey })
    })

    it('should be able to claim something and listen to the connector with a filter', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()
      let observable = await ephemeralConnector.observe(ssid, { 'need': 'wine' })
      let observer = observable.pipe(take(1)).toPromise()
      // TODO: Fix race conditions
      await timeoutPromise(50)

      let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })
      await ephemeralConnector.claim(ssid, { 'need': 'wine' })
      await ephemeralConnector.claim(ssid, { 'need': 'tea' })
      let observed = await observer

      expect(observed.claim.data).to.deep.equal({ 'need': 'wine' })
      expect(observed.claim.previous).to.equal(claimLink)
      expect(observed.claim.signature).to.be.a('string')
      expect(observed.ssid).to.deep.equal({ 'pubkey': ssid.pubkey })
    })

    it('should be able to claim something and listen to the connector with a filter on a predicate', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()
      let observable = await ephemeralConnector.observe(ssid, { 'need': null })
      let observer = observable.pipe(take(1)).toPromise()
      // TODO: Fix race conditions
      await timeoutPromise(50)

      let claimLink = await ephemeralConnector.claim(ssid, { 'desire': 'beer' })
      await ephemeralConnector.claim(ssid, { 'need': 'wine' })
      await ephemeralConnector.claim(ssid, { 'desire': 'tea' })
      let observed = await observer

      expect(observed.claim.data).to.deep.equal({ 'need': 'wine' })
      expect(observed.claim.previous).to.equal(claimLink)
      expect(observed.claim.signature).to.be.a('string')
      expect(observed.ssid).to.deep.equal({ 'pubkey': ssid.pubkey })
    })

    it('should be able to claim something and listen to the connector with a filter on a predicate without an ssid', async () => {
      let ephemeralConnector = new EphemeralConnector()

      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      let ssid = await ephemeralConnector.newSsid()
      let observable = await ephemeralConnector.observe(null, { 'need': null })
      let observer = observable.pipe(take(1)).toPromise()
      // TODO: Fix race conditions
      await timeoutPromise(50)

      let claimLink = await ephemeralConnector.claim(ssid, { 'desire': 'beer' })
      await ephemeralConnector.claim(ssid, { 'need': 'wine' })
      await ephemeralConnector.claim(ssid, { 'desire': 'tea' })
      let observed = await observer

      expect(observed.claim.data).to.deep.equal({ 'need': 'wine' })
      expect(observed.claim.previous).to.equal(claimLink)
      expect(observed.claim.signature).to.be.a('string')
      expect(observed.ssid).to.deep.equal({ 'pubkey': ssid.pubkey })
    })
  })
})
