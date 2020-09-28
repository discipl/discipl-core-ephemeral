/* eslint-env mocha */
/* eslint-disable no-unused-expressions */

import { expect } from 'chai'
import EphemeralConnector from '../src/index'
import EphemeralServer from '../src/EphemeralServer'
import { take, toArray } from 'rxjs/operators'
import { w3cwebsocket } from 'websocket'

import { BaseConnector } from '@discipl/core-baseconnector'
import EphemeralStorage from '../src/EphemeralStorage'

let ephemeralServer

const EPHEMERAL_ENDPOINT = 'https://localhost:3232'
const EPHEMERAL_WEBSOCKET_ENDPOINT = 'wss://localhost:3232'

const CERT_PATH = './test/certs/org.crt'
const KEY_PATH = './test/certs/org.key'

const timeoutPromise = (timeoutMillis) => {
  return new Promise(function (resolve, reject) {
    setTimeout(() => resolve(), timeoutMillis)
  })
}

describe('discipl-ephemeral-connector', () => {
  describe('without a live server', () => {
    it('should present a name', async () => {
      const ephemeralConnector = new EphemeralConnector()
      expect(ephemeralConnector.getName()).to.equal('ephemeral')
    })

    it('should be able to generate an ssid', async () => {
      const ephemeralConnector = new EphemeralConnector()
      const identity = await ephemeralConnector.newIdentity()

      expect(identity.did).to.be.a('string')
      expect(identity.did.length).to.equal(69)
      expect(identity.privkey.length).to.equal(64)
    })

    it('should return deep copy', async () => {
      const ephemeralConnector = new EphemeralConnector()

      const identity = await ephemeralConnector.newIdentity()

      const data = { need: 'beer', wants: ['one', 'two'] }
      const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, data)

      await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

      expect(claimLink).to.be.a('string')
      expect(claimLink.length).to.equal(111)

      const fetchedClaim1 = await ephemeralConnector.get(claimLink)
      fetchedClaim1.data.wants = []

      const fetchedClaim2 = await ephemeralConnector.get(claimLink)
      expect(fetchedClaim2).to.deep.equal({
        data: {
          need: 'beer',
          wants: ['one', 'two']
        },
        previous: null
      })
    })

    it('should claim deep copy', async () => {
      const ephemeralConnector = new EphemeralConnector()

      const identity = await ephemeralConnector.newIdentity()

      const data = { need: 'beer', wants: ['one', 'two'] }
      const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, data)
      data.wants = []

      await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

      expect(claimLink).to.be.a('string')
      expect(claimLink.length).to.equal(111)

      const claim = await ephemeralConnector.get(claimLink)

      expect(claim).to.deep.equal({
        data: {
          need: 'beer',
          wants: ['one', 'two']
        },
        previous: null
      })
    })

    it('should be able to import an identity with a public key', async () => {
      const cert = '-----BEGIN CERTIFICATE-----\r\n' +
        'MIIGGzCCBAOgAwIBAgIUDqjzvfWzZ7dyHuIBerf5m/N09qMwDQYJKoZIhvcNAQEL\r\n' +
        'BQAwgZwxCzAJBgNVBAYTAk5MMRUwEwYDVQQIDAxadWlkLUhvbGxhbmQxETAPBgNV\r\n' +
        'BAcMCERlbiBIYWFnMQ0wCwYDVQQKDARJQ1RVMRAwDgYDVQQLDAdEaXNjaXBsMR4w\r\n' +
        'HAYDVQQDDBV0ZXN0LWNlcnQuZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE25v\r\n' +
        'cmVwbHlAZXhhbXBsZS5jb20wHhcNMTkwNTA5MDcyODUxWhcNMjAwNTA4MDcyODUx\r\n' +
        'WjCBnDELMAkGA1UEBhMCTkwxFTATBgNVBAgMDFp1aWQtSG9sbGFuZDERMA8GA1UE\r\n' +
        'BwwIRGVuIEhhYWcxDTALBgNVBAoMBElDVFUxEDAOBgNVBAsMB0Rpc2NpcGwxHjAc\r\n' +
        'BgNVBAMMFXRlc3QtY2VydC5leGFtcGxlLmNvbTEiMCAGCSqGSIb3DQEJARYTbm9y\r\n' +
        'ZXBseUBleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\r\n' +
        'AL28MtQ1j6n53jpVnwhLgiVegCXdnTuXztd44AsZbO7EhK14mdKkTUH542LfiGWK\r\n' +
        'XwVSOwkmroTQnbD3AzCpG7l3xUx4x5bsiBAgoznsYbKrr4PFeoLmjgb0DA49mNOJ\r\n' +
        'cC16G7SBhJS5WrUh9Twgp4lG07e9pFVvVXKQtcGW3vnt9naoZuIiN3pCIG0ObfRv\r\n' +
        'A/uvn+lQ2r6k0YcWo/BWmJf/7bdhFHH6+oEMasQT/i+mGtRIBgOwu77k/1qDmtco\r\n' +
        'glpu51UKoRdAkruyVO2OFPXJrMVvttnKdoS0GT3ZkxWzH+YPAWrtf+OZTJXT3bGS\r\n' +
        'rhKZrWlmoRo3EFiHjw1vF48E/jiueC9+P+j/fgiV7A613cAmEwL0ggmutOlaKkXq\r\n' +
        'dniaSRSN526KmTvsgSRA/c900dfb1dIvEigYGBQM5GLCZq6ShwPQ3L0OUnEobT1v\r\n' +
        'bKmO+G80fJu2x+q8q1z+XTEOTmfNQDe7MHd3XftrwgONmulYsA94Wa1Fb7shRQgr\r\n' +
        '3u4MmZH1VXFw+mbEU39AxEd3cv5AA05go2OK0vb463XPjCro/h1/SyKDjDGaEkGG\r\n' +
        '1PlBlVrTic48m0R/yek6Y/jm81+I0oasrKt5e+bHHVo8esDf0idohYjtHFgRtZ5S\r\n' +
        'VuSU4LaaYdnSabrEYTobFNXhYQUgBFxAQyRIPLZadsrRAgMBAAGjUzBRMB0GA1Ud\r\n' +
        'DgQWBBSq3yobDJHW0k7fyKPXiFcjYt1rpDAfBgNVHSMEGDAWgBSq3yobDJHW0k7f\r\n' +
        'yKPXiFcjYt1rpDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQC2\r\n' +
        'bXsl/bt2OvLDOP86UXGHEOoSAVggAOmQZJXiNZ/rH71mfhMz0qrrY5zmMITGk6la\r\n' +
        '1GPkrkWUiLi7fhcBTp4Kzr/+kifZ9uaN3EPg6bsqcf4Qs/OTb1HutI31jh0eOfxe\r\n' +
        'VW6aC5B57MdQLdj7gll0r9+GKVlgQq7UgbBmWum54MNGAIsQc0FR6Wv5wBY/AO4q\r\n' +
        'eiMNcpzocGv9RhkVft/hhZqc8A0gmIokDjO+gdUNjaxRTNp57uwK89QZ9NnOso8P\r\n' +
        'kiCU8/R1Lzj4QL7OPq4wGLbQskEpyQgfRiUPyAyLIsds7bx1n8KX9ycG4NY3G9tQ\r\n' +
        'HE+iuxu9WvEelCDSvgLEUU/KpFS3koDrrq5NQB56O5wKad1J8wK1RqKFzNR9DSYH\r\n' +
        '/KGyjIbWlv4ESi9HoJcWKIVoAbtQzmC23bod5ZcuhrSebnVLwsJDhN5MAb21byF2\r\n' +
        'RYEKjatMThWkW7ubwweIlHprX4SsKqEbZD/d17u8Yz52hGwYKWaMo1FiRLMyqzh7\r\n' +
        'xNpWcpBgtAFZbzhQoxN/IQE2t0Zo1P1f+7stRFFeul3WV6UKDbU6Lby9ZsMAUein\r\n' +
        'KGmm+a0d9n9Xm9/u4O1OGLNio57d0RKPWQn+3pZWga+aP202u5QSVeblRiXliUU3\r\n' +
        'OxemhmosTIoo9vBwsjK8aOsi7TVgeceqSMszxeUX+g==\r\n' +
        '-----END CERTIFICATE-----\r\n'

      const ephemeralConnector = new EphemeralConnector()
      const identity = await ephemeralConnector.newIdentity({ cert: cert })

      expect(identity).to.deep.equal({
        did: 'did:discipl:ephemeral:crt:aadf2a1b0c91d6d24edfc8a3d788572362dd6ba4',
        metadata: {
          cert: cert
        },
        privkey: null
      })
    })

    it('should be able to detect wrong signatures when getting a claim', async () => {
      const ephemeralClient = new EphemeralStorage()

      // corrects signature = zxnSFJ1jk0RuoCoEkKJMLXSj08gx+1Syt1W2D3GdczfDwXFsYPH/y55bz85mI1z6QR3NXERcuww85Epq9MErDg==
      const reference = 'IIsy36FkcbWXzkskf501UWlSccfQqrHzXRM9iUXw0QiSdRmyEODtYIdRFnz5jFPgIYH96KzOwKia6FRM+j+qAA=='
      const pubkey = 'ec:DudQN4jBeZM5ht/haJHGIPGi+dl1kKYGdDoR/ZfW/KQ='
      const signature = 'zxnSFJ1jk0RuoCoEkKJMLXSj08gx+2Txu1W2D3GdczfDwXFsYPH/y55bz85mI1z6QR3NXERcuww85Epq9MErDg=='
      let err
      try {
        await ephemeralClient.get(reference, pubkey, signature)
      } catch (e) {
        err = e
      }

      expect(err.message).to.equal('Invalid signature')
    })
  })
  describe('just in server mode', () => {
    before(() => {
      // The 1 in the parameter is for testing with caching, it replaces the 24 hours retentiontime that a claim has normally
      // The awaiting timeoutpromises in the test is used therefore to exceed the retentiontime
      ephemeralServer = new EphemeralServer(3232, CERT_PATH, KEY_PATH, 1)
      ephemeralServer.start()
    })

    after(() => {
      ephemeralServer.close()
    })

    it('should remove stale identities', async () => {
      const ephemeralConnector = new EphemeralConnector()
      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)
      const identity = await ephemeralConnector.newIdentity()
      const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { THIS: 'WILL_DISAPPEAR' })
      const claim = await ephemeralConnector.get(claimLink, identity.did, identity.privkey)
      expect(claim).to.deep.equal({
        data: {
          THIS: 'WILL_DISAPPEAR'
        },
        previous: null
      })
      await timeoutPromise(1500)
      const claimAfterTimeout = await ephemeralConnector.get(claimLink, identity.did, identity.privkey)

      // Even if the timeout is passed, the get method will get the claim from the stored Cache
      expect(claimAfterTimeout).to.deep.equal({
        data: {
          THIS: 'WILL_DISAPPEAR'
        },
        previous: null
      })
      ephemeralConnector.deleteAllFromCache()

      // after awaiting the timeout and also clearing the cache, it's now impossible to get the claim
      const claimAfterClearingCache = await ephemeralConnector.get(claimLink, identity.did, identity.privkey)
      expect(claimAfterClearingCache).to.equal(null)
    }).timeout(5000)

    it('should remove observers of stale identities', async () => {
      const ephemeralConnector = new EphemeralConnector()
      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)

      const identity = await ephemeralConnector.newIdentity()

      const observeResult = await ephemeralConnector.observe(null, { some: 'filter' }, identity.did, identity.privkey)
      observeResult.observable.subscribe(() => { }, () => { })
      await observeResult.readyPromise

      expect(ephemeralServer.storage.globalObservers).to.have.length(1)

      await timeoutPromise(1500)

      expect(ephemeralServer.storage.globalObservers).to.have.length(0)
    }).timeout(5000)

    it('testing how it works with and without caching', async () => {
      const ephemeralConnector = new EphemeralConnector()
      ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)
      const identity = await ephemeralConnector.newIdentity()
      const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
      const claim1 = await ephemeralConnector.get(claimLink, identity.did, identity.privkey)

      const ephemeralConnectorWithoutCaching = new EphemeralConnector()
      ephemeralConnectorWithoutCaching.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket, false)
      const identity2 = await ephemeralConnectorWithoutCaching.newIdentity()
      const claimlink2 = await ephemeralConnectorWithoutCaching.claim(identity2.did, identity2.privkey, { need: 'tea' })
      const claim2 = await ephemeralConnectorWithoutCaching.get(claimlink2, identity2.did, identity2.privkey)

      expect(claim1).to.deep.equal({
        data: {
          need: 'beer'
        },
        previous: null
      })
      expect(claim2).to.deep.equal({
        data: {
          need: 'tea'
        },
        previous: null
      })
      await timeoutPromise(3000)

      const claimWithCaching = await ephemeralConnector.get(claimLink, identity.did, identity.privkey)
      const claimWithoutCaching = await ephemeralConnectorWithoutCaching.get(claimlink2, identity2.did, identity2.privkey)
      // After awaiting the timout, the get method can only get the claims from the cache.
      // With these two expect's we can see that the claim with caching will get the data back
      // And the claim without caching, can't get anything back
      expect(claimWithCaching).to.deep.equal({
        data: {
          need: 'beer'
        },
        previous: null
      })
      expect(claimWithoutCaching).to.equal(null)
    }).timeout(5000)
  })
  describe('with a backend', () => {
    before(() => {
      ephemeralServer = new EphemeralServer(3232, CERT_PATH, KEY_PATH)
      ephemeralServer.start()
    })

    after(() => {
      ephemeralServer.close()
    })

    const backends = [
      {
        description: 'in memory',
        createConnector: () => new EphemeralConnector()
      },
      {
        description: 'in a server',
        createConnector: () => {
          const ephemeralConnector = new EphemeralConnector()
          ephemeralConnector.configure(EPHEMERAL_ENDPOINT, EPHEMERAL_WEBSOCKET_ENDPOINT, w3cwebsocket)
          return ephemeralConnector
        }
      }
    ]
    backends.forEach((backend) => {
      describe(backend.description, () => {
        it('should be able to claim something', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          expect(claimLink).to.be.a('string')
          expect(claimLink.length).to.equal(111)

          const claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })
        })

        it('should be able to import an identity with a public and private key and claim something', async () => {
          const cert = '-----BEGIN CERTIFICATE-----\r\n' +
            'MIIGGzCCBAOgAwIBAgIUDqjzvfWzZ7dyHuIBerf5m/N09qMwDQYJKoZIhvcNAQEL\r\n' +
            'BQAwgZwxCzAJBgNVBAYTAk5MMRUwEwYDVQQIDAxadWlkLUhvbGxhbmQxETAPBgNV\r\n' +
            'BAcMCERlbiBIYWFnMQ0wCwYDVQQKDARJQ1RVMRAwDgYDVQQLDAdEaXNjaXBsMR4w\r\n' +
            'HAYDVQQDDBV0ZXN0LWNlcnQuZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE25v\r\n' +
            'cmVwbHlAZXhhbXBsZS5jb20wHhcNMTkwNTA5MDcyODUxWhcNMjAwNTA4MDcyODUx\r\n' +
            'WjCBnDELMAkGA1UEBhMCTkwxFTATBgNVBAgMDFp1aWQtSG9sbGFuZDERMA8GA1UE\r\n' +
            'BwwIRGVuIEhhYWcxDTALBgNVBAoMBElDVFUxEDAOBgNVBAsMB0Rpc2NpcGwxHjAc\r\n' +
            'BgNVBAMMFXRlc3QtY2VydC5leGFtcGxlLmNvbTEiMCAGCSqGSIb3DQEJARYTbm9y\r\n' +
            'ZXBseUBleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\r\n' +
            'AL28MtQ1j6n53jpVnwhLgiVegCXdnTuXztd44AsZbO7EhK14mdKkTUH542LfiGWK\r\n' +
            'XwVSOwkmroTQnbD3AzCpG7l3xUx4x5bsiBAgoznsYbKrr4PFeoLmjgb0DA49mNOJ\r\n' +
            'cC16G7SBhJS5WrUh9Twgp4lG07e9pFVvVXKQtcGW3vnt9naoZuIiN3pCIG0ObfRv\r\n' +
            'A/uvn+lQ2r6k0YcWo/BWmJf/7bdhFHH6+oEMasQT/i+mGtRIBgOwu77k/1qDmtco\r\n' +
            'glpu51UKoRdAkruyVO2OFPXJrMVvttnKdoS0GT3ZkxWzH+YPAWrtf+OZTJXT3bGS\r\n' +
            'rhKZrWlmoRo3EFiHjw1vF48E/jiueC9+P+j/fgiV7A613cAmEwL0ggmutOlaKkXq\r\n' +
            'dniaSRSN526KmTvsgSRA/c900dfb1dIvEigYGBQM5GLCZq6ShwPQ3L0OUnEobT1v\r\n' +
            'bKmO+G80fJu2x+q8q1z+XTEOTmfNQDe7MHd3XftrwgONmulYsA94Wa1Fb7shRQgr\r\n' +
            '3u4MmZH1VXFw+mbEU39AxEd3cv5AA05go2OK0vb463XPjCro/h1/SyKDjDGaEkGG\r\n' +
            '1PlBlVrTic48m0R/yek6Y/jm81+I0oasrKt5e+bHHVo8esDf0idohYjtHFgRtZ5S\r\n' +
            'VuSU4LaaYdnSabrEYTobFNXhYQUgBFxAQyRIPLZadsrRAgMBAAGjUzBRMB0GA1Ud\r\n' +
            'DgQWBBSq3yobDJHW0k7fyKPXiFcjYt1rpDAfBgNVHSMEGDAWgBSq3yobDJHW0k7f\r\n' +
            'yKPXiFcjYt1rpDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQC2\r\n' +
            'bXsl/bt2OvLDOP86UXGHEOoSAVggAOmQZJXiNZ/rH71mfhMz0qrrY5zmMITGk6la\r\n' +
            '1GPkrkWUiLi7fhcBTp4Kzr/+kifZ9uaN3EPg6bsqcf4Qs/OTb1HutI31jh0eOfxe\r\n' +
            'VW6aC5B57MdQLdj7gll0r9+GKVlgQq7UgbBmWum54MNGAIsQc0FR6Wv5wBY/AO4q\r\n' +
            'eiMNcpzocGv9RhkVft/hhZqc8A0gmIokDjO+gdUNjaxRTNp57uwK89QZ9NnOso8P\r\n' +
            'kiCU8/R1Lzj4QL7OPq4wGLbQskEpyQgfRiUPyAyLIsds7bx1n8KX9ycG4NY3G9tQ\r\n' +
            'HE+iuxu9WvEelCDSvgLEUU/KpFS3koDrrq5NQB56O5wKad1J8wK1RqKFzNR9DSYH\r\n' +
            '/KGyjIbWlv4ESi9HoJcWKIVoAbtQzmC23bod5ZcuhrSebnVLwsJDhN5MAb21byF2\r\n' +
            'RYEKjatMThWkW7ubwweIlHprX4SsKqEbZD/d17u8Yz52hGwYKWaMo1FiRLMyqzh7\r\n' +
            'xNpWcpBgtAFZbzhQoxN/IQE2t0Zo1P1f+7stRFFeul3WV6UKDbU6Lby9ZsMAUein\r\n' +
            'KGmm+a0d9n9Xm9/u4O1OGLNio57d0RKPWQn+3pZWga+aP202u5QSVeblRiXliUU3\r\n' +
            'OxemhmosTIoo9vBwsjK8aOsi7TVgeceqSMszxeUX+g==\r\n' +
            '-----END CERTIFICATE-----\r\n'

          const key = '-----BEGIN PRIVATE KEY-----\r\n' +
            'MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC9vDLUNY+p+d46\r\n' +
            'VZ8IS4IlXoAl3Z07l87XeOALGWzuxISteJnSpE1B+eNi34hlil8FUjsJJq6E0J2w\r\n' +
            '9wMwqRu5d8VMeMeW7IgQIKM57GGyq6+DxXqC5o4G9AwOPZjTiXAtehu0gYSUuVq1\r\n' +
            'IfU8IKeJRtO3vaRVb1VykLXBlt757fZ2qGbiIjd6QiBtDm30bwP7r5/pUNq+pNGH\r\n' +
            'FqPwVpiX/+23YRRx+vqBDGrEE/4vphrUSAYDsLu+5P9ag5rXKIJabudVCqEXQJK7\r\n' +
            'slTtjhT1yazFb7bZynaEtBk92ZMVsx/mDwFq7X/jmUyV092xkq4Sma1pZqEaNxBY\r\n' +
            'h48NbxePBP44rngvfj/o/34IlewOtd3AJhMC9IIJrrTpWipF6nZ4mkkUjeduipk7\r\n' +
            '7IEkQP3PdNHX29XSLxIoGBgUDORiwmaukocD0Ny9DlJxKG09b2ypjvhvNHybtsfq\r\n' +
            'vKtc/l0xDk5nzUA3uzB3d137a8IDjZrpWLAPeFmtRW+7IUUIK97uDJmR9VVxcPpm\r\n' +
            'xFN/QMRHd3L+QANOYKNjitL2+Ot1z4wq6P4df0sig4wxmhJBhtT5QZVa04nOPJtE\r\n' +
            'f8npOmP45vNfiNKGrKyreXvmxx1aPHrA39InaIWI7RxYEbWeUlbklOC2mmHZ0mm6\r\n' +
            'xGE6GxTV4WEFIARcQEMkSDy2WnbK0QIDAQABAoICABDYs/6pns7t07CER7GZ2r1s\r\n' +
            'rZ4vFjXjXcc+AU6a/FQa+NjaO3Y7hmyUPn9Z76dsaNF1Iq7GU3qRd17uH8djTIXk\r\n' +
            'P41xr+8To2UjMLsE5QvTOKtPjngu9m9hnexpxbcKnf47uFgHo/j8mDQ7BqZHE/kZ\r\n' +
            'Y9UNrpizYPfiJ3E/7x5r5ZVVkIUFmr1tP6nPPS4V6Vmgl2dE+Zcx1TTUasv9NGFS\r\n' +
            'pQ3CPel86l8o9hXg3JHogrtUhcwwFgt2E8I6qzXtb92NuVaQsgr5fc3SoL3S/sNw\r\n' +
            'G7oQGEEwO+O+hfs65Vdo5y0rKeoPmmpgAy/OdwG8T15xbLdOGIHWX8oshyQfOA0g\r\n' +
            'lRZhoWmyRSfhe8fl0AMenMKDD9NHX+GBCEcFsgNd4qqahEd0BVFIR5K97m+9bV+V\r\n' +
            'XNpZcwfqXEuhkbO2pAI5Xs3CXk+EXGI0WD4KaxViPP3EZJvrr74EtWiq6o6+7qVg\r\n' +
            'dFIblJjG4dLIftdAI60EXMwVItwfk5zKdJVLvm8o0bXvoATbsKLaG2Ddl7jtmO4l\r\n' +
            'ATCef+2MY9uaRaZQ2y2hBKRSvv2rYBXJ/2YqIj4thHZs8Z+oGvgg130y90NczRc6\r\n' +
            '8LbauOIgWgUQ7P+Mx5uloltT379Q4PRtW0eMP6yIT9zhTcoGZjeAvrIsGmQH0Jft\r\n' +
            'ijfLT2eufyKny61LdjfBAoIBAQDvDDx87eoUofUwO+hhwOWl1fXSuYEkJHzjpp6U\r\n' +
            'H6XL7iFSsj3dqIhWEOX9GIsa8DDS5eFUSsqLTt95kkLJLwxm2sJjBSxiPLWxDqnO\r\n' +
            '4l2uoZQpcP/s7xy85DtrpTvpyb/eJJBDHeFI1V7yEzTa0NI/n1xbuZhgRcVqmMG9\r\n' +
            'M1CREyaaOUTeDqHahDz3kB/p40lNS7qQNBbOSs5S0L1raqrPHP0iNpkbkmHdR9Uq\r\n' +
            '5LVrc57aUcN2+2vnc5wyM7wPZNK/ThwrM8SzLGg8JzD/LosFJ0WE4eg2+uUYQDvE\r\n' +
            'LVwnbgt5olnYs47XBPJQLMVNiJPNgt6As+G/suWhZJu6vbvZAoIBAQDLMLjOsfBu\r\n' +
            'MuimqrnvoVStUEljN3DeFaAcO+lI1WPlbVnpRYoVAGopDnjM0lRvsaDMwKRKrtMj\r\n' +
            'Sqcq+vXlcRvfhtuMYAPsoLUyIZQcpkp3yoLsnhPkL36EL+jYmlv3b09DtcL0b6m/\r\n' +
            '+oAGKqCZsz4PpsyP55V5fd7giuA2SJTtKHwdVo6njfgSxyg3pGv+2n47x7n0rf/n\r\n' +
            'zuHwMx68/qNPhfPdEgY+P/A0Ab9PFqgkPSYTrHIy3dOgAVZHUbUmZsDKsGcRyU5v\r\n' +
            'v/3GlrlPbUXbVborEeTNfNs//2XWV9/5WupjfvmKz1YoeoUFLwoFWTySkERiBbB8\r\n' +
            'p/NhoJRvyoO5AoIBAHsfR0xlUep8nIfSY1dt/hpTQIDfsOdHr9elKwpJ3qBRr3Ij\r\n' +
            'gf/X3RjPLVYVvRgL3GnToyJCP15PKoU4UxPCGtYjGHnd4UVb1Y0zazy2lN/sMx7B\r\n' +
            'J+AGLDwSJZTFDz3T/vHQzUj0a+OSmot+XvvREGlakDxiNFxps0u7EBZ+BqIiRgCr\r\n' +
            'PJBO4whkke5EmltiCJA6UAYT/icUmn5HKzjXQNDaMnrbujJcS/GoHOAx2ktUyt3R\r\n' +
            'vSZcSvB0OGAXC2a2XGHSPmn2CPrsBWfuG6tjcpEd8A2IOY2P3k2GUAI0BsH8SQbG\r\n' +
            'GxalLQ4May3mUV0k2lPAcw/BFqYg42skIZ2mOckCggEAIDdWZfdSjrZlqt9Q4cyr\r\n' +
            'l1sud5u3uo6lNzTMlS64Sw0ef1z2OsQ5EM9pmdgTaS45t50nr2uusF7KyIbH7BwV\r\n' +
            '9kf0kXo7xQ3qDMvEJxK6pemm/otFzh01qxHJkmZPBJlScQLlqUn3GShHmjKyCgyg\r\n' +
            'X2zr7DkkuwGZD/MU/6ZcbonHvAMYVTquRZPsLX5VXTAZabMOKdxYwdFMg4AndIHP\r\n' +
            'NPGhK8EK2l3a4PQR+CE4gZ5sZhwmcyg2wJzVqDMtTKxoDvsPLIPFevRu8Ui+kvhZ\r\n' +
            'ZiBehyusImSUgr4k0GpYabnfhe0A9eBP4dUjOCIwLY7rirVzEjOiuvEKJsWGI39x\r\n' +
            'iQKCAQEA2+vQTbTzpnyjTXtv4R9xHreaHxq9WLc1sd3vOa8vavejnmEZPVPP4VPn\r\n' +
            'Pl1Ms1LHI09ppNMnYAMt5HsMC3wehhTq1BecA7lGyOJCUve9U9iTXN5MbanjkFdQ\r\n' +
            'DGRvGDYyQuaQJXZzoC+OGV2WSZ5qMavylRlsgNY43DLkMyDeOXRoTX6AnaerHu4d\r\n' +
            'T/HTIKN3WIX7r85bACLuHpBFJAJ5wN6Me+suyocWbRDMxem7HyyuXfYHQRyJwxSP\r\n' +
            'W8+UZvp2V65zvkXFRI78BlEhAW1sqB+Uz0LMYvSjVkFwuPBojfPj2UFBgFMXJzFT\r\n' +
            'gnrcsERJiRcbv67DYoSeBsigf8zA2Q==\r\n' +
            '-----END PRIVATE KEY-----\r\n'

          const ephemeralConnector = backend.createConnector()
          const identity = await ephemeralConnector.newIdentity({ cert: cert, privkey: key })

          expect(identity).to.deep.equal({
            did: 'did:discipl:ephemeral:crt:aadf2a1b0c91d6d24edfc8a3d788572362dd6ba4',
            metadata: {
              cert: cert
            },
            privkey: key
          })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          expect(claimLink).to.be.a('string')

          const claim = await ephemeralConnector.get(claimLink, identity)

          expect(claim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })
        })

        it('should be able to claim multiple things', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })
          expect(claimLink).to.be.a('string')

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })

          const claim2 = await ephemeralConnector.get(claimLink2)

          expect(claim2).to.deep.equal({
            data: {
              need: 'wine'
            },
            previous: claimLink
          })
        })

        it('should be stable if the same thing is claimed twice', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })

          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const claim2 = await ephemeralConnector.get(claimLink2)

          expect(claim2).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })

          expect(claimLink).to.equal(claimLink2)
        })

        it('should be able to claim something complicated', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: { for: 'speed' } })

          expect(claimLink).to.be.a('string')

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claim = await ephemeralConnector.get(claimLink)

          expect(claim).to.deep.equal({
            data: {
              need: {
                for: 'speed'
              }
            },
            previous: null
          })
        })

        it('should not be able to claim something with a wrong key', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const wrongIdentity = await ephemeralConnector.newIdentity()

          try {
            await ephemeralConnector.claim(identity.did, wrongIdentity.privkey, { need: 'beer' })
            expect.fail(null, null, 'Managed to claim something')
          } catch (e) {
            expect(e).to.not.equal(null)
          }
        })

        it('should not be able to access a claim with a wrong key', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const wrongIdentity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')

          try {
            await ephemeralConnector.get(claimLink, identity.did, wrongIdentity.privkey)
            expect.fail(null, null, 'Managed to claim something')
          } catch (e) {
            expect(e).to.not.equal(null)
          }
        })

        it('should be able to claim something and grant a specific did access to the claim', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const accessorIdentity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          const allowClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, {
            [BaseConnector.ALLOW]: {
              scope: claimLink,
              did: accessorIdentity.did
            }
          })

          expect(claimLink).to.be.a('string')

          // Check that without authentication it is not possible to obtain the claim
          const claim = await ephemeralConnector.get(claimLink)
          expect(claim).to.deep.equal(null)

          const authorizedClaim = await ephemeralConnector.get(claimLink, accessorIdentity.did, accessorIdentity.privkey)
          expect(authorizedClaim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })

          const allowClaim = await ephemeralConnector.get(allowClaimLink, accessorIdentity.did, accessorIdentity.privkey)
          expect(allowClaim).to.deep.equal(null)
        })

        it('should be able to claim something and grant a specific did access to the channel', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const accessorIdentity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          const allowClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, {
            [BaseConnector.ALLOW]: {
              did: accessorIdentity.did
            }
          })

          expect(claimLink).to.be.a('string')

          // Check that without authentication it is not possible to obtain the claim
          const claim = await ephemeralConnector.get(claimLink)
          expect(claim).to.deep.equal(null)

          const authorizedClaim = await ephemeralConnector.get(claimLink, accessorIdentity.did, accessorIdentity.privkey)
          expect(authorizedClaim).to.deep.equal({
            data: {
              need: 'beer'
            },
            previous: null
          })

          const allowClaim = await ephemeralConnector.get(allowClaimLink, accessorIdentity.did, accessorIdentity.privkey)
          expect(allowClaim).to.deep.equal({
            data: {
              DISCIPL_ALLOW: {
                did: accessorIdentity.did
              }
            },
            previous: claimLink
          })
        })

        it('should be able to obtain a reference to the last claim', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')

          const latestClaimLink = await ephemeralConnector.getLatestClaim(identity.did)

          expect(claimLink).to.equal(latestClaimLink)
        })

        it('should be able to obtain the last claim', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const beerLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const wineLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })

          const latestClaimLink = await ephemeralConnector.getLatestClaim(identity.did)

          expect(wineLink).to.equal(latestClaimLink)

          const wineClaim = await ephemeralConnector.get(wineLink)

          expect(wineClaim).to.deep.equal({
            data: {
              need: 'wine'
            },
            previous: beerLink
          })
        })

        it('should be able to get the ssid from a claim reference', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLinkDid = await ephemeralConnector.getDidOfClaim(claimLink)

          expect(claimLinkDid).to.be.a('string')
          expect(claimLinkDid).to.equal(identity.did)
        })

        it('should be able to claim something and listen to the connector', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did)
          const accessClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const observer = observeResult.observable.pipe(take(1)).toPromise()
          await observeResult.readyPromise

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'beer'
              },
              previous: accessClaimLink
            },
            did: identity.did,
            link: claimLink
          })
        })

        it('should be able to claim something and listen to the connector to get multiple claims', async function () {
          this.timeout(5000)
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did)
          const accessClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const observer = observeResult.observable.pipe(take(2)).pipe(toArray()).toPromise()

          await observeResult.readyPromise

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })
          expect(claimLink).to.be.a('string')
          expect(claimLink2).to.be.a('string')

          const observed = await observer

          expect(observed).to.deep.equal([{
            claim: {
              data: {
                need: 'beer'
              },
              previous: accessClaimLink
            },
            did: identity.did,
            link: claimLink
          },
          {
            claim: {
              data: {
                need: 'wine'
              },
              previous: claimLink
            },
            did: identity.did,
            link: claimLink2
          }
          ])
        })

        it('should be able to control access on observed claims', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did, { need: null })
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const allowClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })

          expect(claimLink).to.be.a('string')
          expect(claimLink2).to.be.a('string')
          const observed = await observer

          expect(observed).to.deep.equal(
            {
              claim: {
                data: {
                  need: 'wine'
                },
                previous: allowClaimLink
              },
              did: identity.did,
              link: claimLink2
            }
          )
        })

        it('should be able to control access on observed claims to a specific did', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const accessorIdentity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did, { need: null }, accessorIdentity.did, accessorIdentity.privkey)
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const allowClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, {
            [BaseConnector.ALLOW]: {
              did: accessorIdentity.did
            }
          })

          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })

          expect(claimLink).to.be.a('string')
          expect(claimLink2).to.be.a('string')
          const observed = await observer

          expect(observed).to.deep.equal(
            {
              claim: {
                data: {
                  need: 'wine'
                },
                previous: allowClaimLink
              },
              did: identity.did,
              link: claimLink2
            }
          )
        })

        it('should not be able to observe claims with a faulty key', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const wrongIdentity = await ephemeralConnector.newIdentity()

          await ephemeralConnector.observe(identity.did, {}, identity.did, wrongIdentity.privkey)
            .then((result) => {
              expect.fail(null, null, 'Observable succeeded')
            })
            .catch((e) => {
              expect(e.message).to.be.a('string')
            })
        })

        it('should be able to import a claim using the signature from reference and importing it under same claim id', async () => {
          let ephemeralConnector = backend.createConnector()
          const identity = await ephemeralConnector.newIdentity()
          const reference = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claim = await ephemeralConnector.get(reference)
          expect(claim.data).to.deep.equal({ need: 'beer' })

          // Purposefully create local-memory connector
          ephemeralConnector = new EphemeralConnector()
          await ephemeralConnector.newIdentity({ cert: identity.metadata.cert })
          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })
          let c = await ephemeralConnector.get(reference)
          expect(c).to.equal(null)

          const result = await ephemeralConnector.import(identity.did, reference, claim.data)
          expect(reference).to.equal(result)
          c = await ephemeralConnector.get(result)
          expect(c.data).to.deep.equal({ need: 'beer' })
        })

        it('should be able to import a claim using the signature from reference and be able to be accessed by the original owner', async () => {
          let ephemeralConnector = backend.createConnector()
          const identity = await ephemeralConnector.newIdentity()
          const reference = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          const claim = await ephemeralConnector.get(reference, identity.did, identity.privkey)
          expect(claim.data).to.deep.equal({ need: 'beer' })

          // Purposefully create local-memory connector
          ephemeralConnector = new EphemeralConnector()
          await ephemeralConnector.newIdentity({ cert: identity.metadata.cert })
          let c = await ephemeralConnector.get(reference)
          expect(c).to.equal(null)

          const result = await ephemeralConnector.import(identity.did, reference, claim.data)
          c = await ephemeralConnector.get(result, identity.did, identity.privkey)
          expect(c.data).to.deep.equal({ need: 'beer' })
          expect(reference).to.equal(result)
        })

        it('should be able to import a claim using the signature from reference and be able to be accessed by the importer', async () => {
          let ephemeralConnector = backend.createConnector()
          const identity = await ephemeralConnector.newIdentity()
          const reference = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          const claim = await ephemeralConnector.get(reference, identity.did, identity.privkey)
          expect(claim.data).to.deep.equal({ need: 'beer' })

          // Purposefully create local-memory connector
          ephemeralConnector = new EphemeralConnector()
          await ephemeralConnector.newIdentity({ cert: identity.metadata.cert })
          let c = await ephemeralConnector.get(reference)
          expect(c).to.equal(null)

          const importerIdentity = await ephemeralConnector.newIdentity()

          const result = await ephemeralConnector.import(identity.did, reference, claim.data, importerIdentity.did)
          c = await ephemeralConnector.get(result, importerIdentity.did, importerIdentity.privkey)
          expect(c.data).to.deep.equal({ need: 'beer' })
          expect(reference).to.equal(result)
        })

        it('should be able to observe connector-wide', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(null, { need: 'beer' })
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          const accessClaimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'beer'
              },
              previous: accessClaimLink
            },
            did: identity.did,
            link: claimLink
          })
        })

        it('should be able to observe connector-wide with credentials', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(null, { need: 'beer' }, identity.did, identity.privkey)
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })

          expect(claimLink).to.be.a('string')
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'beer'
              },
              previous: null
            },
            did: identity.did,
            link: claimLink
          })
        })

        it('should be able to claim something and listen to the connector with a filter', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did, { need: 'wine' })
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'beer' })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })
          await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'tea' })
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'wine'
              },
              previous: claimLink
            },
            did: identity.did,
            link: claimLink2
          })
        })

        it('should be able to claim something and listen to the connector with a filter on a predicate', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(identity.did, { need: null })
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { desire: 'beer' })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })
          await ephemeralConnector.claim(identity.did, identity.privkey, { desire: 'tea' })
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'wine'
              },
              previous: claimLink
            },
            did: identity.did,
            link: claimLink2
          })
        })

        it('should be able to claim something and listen to the connector with a filter on a predicate without an ssid', async () => {
          const ephemeralConnector = backend.createConnector()

          const identity = await ephemeralConnector.newIdentity()
          const observeResult = await ephemeralConnector.observe(null, { need: null })
          const observer = observeResult.observable.pipe(take(1)).toPromise()

          await observeResult.readyPromise

          await ephemeralConnector.claim(identity.did, identity.privkey, { [BaseConnector.ALLOW]: {} })

          const claimLink = await ephemeralConnector.claim(identity.did, identity.privkey, { desire: 'beer' })
          const claimLink2 = await ephemeralConnector.claim(identity.did, identity.privkey, { need: 'wine' })
          await ephemeralConnector.claim(identity.did, identity.privkey, { desire: 'tea' })
          const observed = await observer

          expect(observed).to.deep.equal({
            claim: {
              data: {
                need: 'wine'
              },
              previous: claimLink
            },
            did: identity.did,
            link: claimLink2
          })
        })
      })
    })
  })
})
