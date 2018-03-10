'use strict'

const { asn1, pki, util: { ByteBuffer } } = require('node-forge')
const strftime = require('strftime')

class CertError extends Error {
  constructor (message, severe, endDate) {
    super(message)
    this.severe = severe || false
    this.endDate = endDate
  }
}

module.exports.CertError = CertError

module.exports.checkCert = (certificate, days) => {
  const now = new Date()
  const validFrom = new Date(certificate.valid_from)
  const validTo = new Date(certificate.valid_to)
  const lifetimeDays = Math.floor((validTo - validFrom) / 86400000)
  var endDate = validTo
  var endReason = 'expiry'

  if (validTo.getTime() <= now.getTime()) {
    throw new CertError(
      `Certificate expired on ${strftime('%d %b %Y', validTo)}!`,
      true, validTo)
  }

  const forgeCert = pki.certificateFromAsn1(
    asn1.fromDer(new ByteBuffer(certificate.raw)))
  const sigAlg = pki.oids[forgeCert.siginfo.algorithmOid]
  if (!sigAlg) {
    throw new CertError('Signature algorithm is unknown', false, validTo)
  }
  if (/md5|sha1\b/i.test(sigAlg)) {
    throw new CertError(`Signature algorithm is ${sigAlg}`)
  }

  if (/symantec|thawte|rapidssl|geotrust/i.test(certificate.issuer.CN)) {
    const distrustDate = new Date(
      validFrom.getTime() < new Date('2016-06-01').getTime()
      ? '2018-03-15' : '2018-09-13')
    if (distrustDate.getTime() < validTo.getTime()) {
      endDate = distrustDate
      endReason = 'distrust'
    }
  }

  const daysToLive = Math.floor((endDate - now) / 86400000)

  if (daysToLive < days) {
    throw new CertError(
      `Certificate ${endReason} date is ${strftime('%d %b %Y', endDate)}` +
      ` - ${daysToLive} day${daysToLive === 1 ? '' : 's'}`, false, endDate)
  }
  if (validFrom.getTime() >= new Date('2018-03-01').getTime() &&
      lifetimeDays > 825) {
    throw new CertError(
      `Certificate lifetime of ${lifetimeDays} is too long`, true)
  }

  return endDate
}
