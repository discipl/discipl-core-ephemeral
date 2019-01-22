/* eslint-env mocha */
/* eslint-disable no-unused-expressions */

import { expect } from 'chai'
import EphemeralConnector from '../src/index'
import { EphemeralServer } from '../src/server'
import { take } from 'rxjs/operators'

let ephemeralServer

const EPHEMERAL_ENDPOINT = 'http://localhost:3232'
const EPHEMERAL_WEBSOCKET_ENDPOINT = 'ws://localhost:3233'

const timeoutPromise = (timeoutMillis) => {
  return new Promise(function (resolve, reject) {
    setTimeout(() => resolve(), timeoutMillis)
  })
}

describe('discipl-ephemeral-connector', () => {
  before(() => {
    ephemeralServer = new EphemeralServer(3232)
  })

  after(() => {
    ephemeralServer.close()
  })

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

  it('should be able to claim something', async () => {
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT)

    let ssid = await ephemeralConnector.newSsid()

    let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

    expect(claimLink).to.be.a('string')

    let claim = await ephemeralConnector.get(claimLink)

    expect(claim).to.deep.equal({ 'data': { 'need': 'beer' }, 'previous': null })
  })

  it('should be able to obtain a reference to the last claim', async () => {
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT)

    let ssid = await ephemeralConnector.newSsid()

    let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

    expect(claimLink).to.be.a('string')

    let latestClaimLink = await ephemeralConnector.getLatestClaim(ssid)

    expect(claimLink).to.equal(latestClaimLink)
  })

  it('should be able to get the ssid from a claim reference', async () => {
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT)

    let ssid = await ephemeralConnector.newSsid()

    let claimLink = await ephemeralConnector.claim(ssid, { 'need': 'beer' })

    expect(claimLink).to.be.a('string')

    let claimLinkSsid = await ephemeralConnector.getSsidOfClaim(claimLink)

    expect(claimLinkSsid.pubkey).to.be.a('string')
    expect(ssid.pubkey).to.equal(claimLinkSsid.pubkey)
  })

  it('should be able to claim something and listen to the connector', async () => {
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT)

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

  it('should be able to observe connector-wide', async () => {
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT)

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
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT)

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
    let ephemeralConnector = new EphemeralConnector()

    ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT)

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
})
