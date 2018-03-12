'use strict'

const { asn1, pki, util: { ByteBuffer } } = require('node-forge')
const strftime = require('strftime')

/** check-cert module. Provides a function to check whether a certificate
  * has problems.
  * @module check-cert
  */

/** Class representing an error with a TLS certificate.
  *
  * @property {string} message - The message.
  * @property {boolean} severe - Is the error 'severe'?
  *   (Is it likely to mean the certificate is already failing).
  * @property {Date} endDate - The date the certificate will fail.
  * @extends Error
  */
const CertError = module.exports.CertError = class extends Error {
  /** Create a certificate error.
    *
    * @param {string} message - The message.
    * @param {boolean} [severe=false] - Is the error 'severe'?
    *   (Is it likely to mean the certificate is already failing).
    * @param {Date} [endDate] - The date the certificate will fail.
    */
  constructor (message, severe, endDate) {
    super(message)
    this.severe = severe || false
    this.endDate = endDate
  }
}

/** Check a certificate to see if it has any problems, such as expiring
  * soon or using a deprecated signature algorithm.
  *
  * @param {certificate} certificate - The certificate to check.
  * @param {integer} days - The number of days to consider 'soon'.
  * @returns {Date} - the date the certificate will fail.
  * @throws {CertError} There was a problem with a certificate.
  */
module.exports.checkCert = (certificate, days) => {
  const now = new Date()
  const validFrom = new Date(certificate.valid_from)
  const validTo = new Date(certificate.valid_to)
  const lifetimeDays = Math.floor((validTo - validFrom) / 86400000)
  var endDate = validTo
  var endReason = 'expiry'

  /* Check if the certificate has already expired. */

  if (validTo.getTime() <= now.getTime()) {
    throw new CertError(
      `Certificate expired on ${strftime('%d %b %Y', validTo)}!`,
      true, validTo)
  }

  /* Check if the certificate uses a deprecated algorithm.
     Requires converting the certificate to a node-forge one. */

  const forgeCert = pki.certificateFromAsn1(
    asn1.fromDer(new ByteBuffer(certificate.raw)))
  const sigAlg = pki.oids[forgeCert.siginfo.algorithmOid]
  if (!sigAlg) {
    throw new CertError('Signature algorithm is unknown', false, validTo)
  }
  if (/md5|sha1\b/i.test(sigAlg)) {
    throw new CertError(`Signature algorithm is ${sigAlg}`)
  }

  /* Check if the certificate is issued by one of the Symantec CAs
     that are going to be distrusted during 2018. */

  if (/symantec|thawte|rapidssl|geotrust/i.test(certificate.issuer.CN)) {
    const distrustDate = new Date(
      validFrom.getTime() < new Date('2016-06-01').getTime()
      ? '2018-03-15' : '2018-09-13')
    if (distrustDate.getTime() < validTo.getTime()) {
      endDate = distrustDate
      endReason = 'distrust'
    }
  }

  /* Check if the certificate will expire or become distrusted soon. */

  const daysToLive = Math.floor((endDate - now) / 86400000)

  if (daysToLive < days) {
    throw new CertError(
      `Certificate ${endReason} date is ${strftime('%d %b %Y', endDate)}` +
      ` - ${daysToLive} day${daysToLive === 1 ? '' : 's'}`, false, endDate)
  }

  /* Check if the certificate has a too-long validity period. */

  if (validFrom.getTime() >= new Date('2018-03-01').getTime() &&
      lifetimeDays > 825) {
    throw new CertError(
      `Certificate lifetime of ${lifetimeDays} is too long`, true)
  }

  /* No problems found - return the certificate failure date. */

  return endDate
}
