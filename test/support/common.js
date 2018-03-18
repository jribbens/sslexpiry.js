'use strict'

const { expect, use } = require('chai')
use(require('chai-moment'))
use(require('chai-as-promised'))
const { asn1, md, pki } = require('node-forge')

module.exports.expect = expect

const DAYS = 86400 * 1000

const keys = pki.rsa.generateKeyPair(1024)

/* Generate a self-signed node-forge certificate with the desired settings. */

module.exports.makeCert = (
    { notAfter = 60, notBefore = -60,
      commonName = 'localhost', signature = 'sha256' } = {}) => {
  const now = new Date()
  const cert = pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = (typeof notBefore === 'number')
    ? new Date(+now + notBefore * DAYS) : notBefore
  cert.validity.notAfter = (typeof notAfter === 'number')
    ? new Date(+now + notAfter * DAYS) : notAfter
  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'Test' }
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.sign(keys.privateKey, md[signature].create())
  return cert
}

/* Convert a node-forge certificate into something that looks like
   node's tls.tlsSocket.getPeerCertificate() output, or at least
   close enough for our purposes. */

module.exports.getNodeCert = (nodeCert) => {
  return {
    issuer: { CN: nodeCert.issuer.getField('CN').value },
    raw: asn1.toDer(pki.certificateToAsn1(nodeCert)),
    subject: { CN: nodeCert.subject.getField('CN').value },
    valid_from: nodeCert.validity.notBefore,
    valid_to: nodeCert.validity.notAfter
  }
}

module.exports.getPEMKey = () => {
  return pki.privateKeyToPem(keys.privateKey)
}

module.exports.getPEMCert = (cert) => {
  return pki.certificateToPem(cert)
}
