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
    this.severe = !!severe
    this.endDate = endDate
  }
}

/** Compare two checkCert results and indicate which of the two is
  * more important/urgent.
  *
  * @param a - The first result.
  * @param b - The second result.
  * @returns {integer} - less than zero if 'a' is more important,
  *                      greater than zero if 'b' is more important,
  *                      zero if they are equally important.
  */
const compareResults = module.exports.compareResults = (a, b) => {
  if (a instanceof Date) {
    if (b instanceof Date) return a - b
    return 1
  }
  if (b instanceof Date) return -1
  if (a instanceof CertError && b instanceof CertError &&
      a.severe !== b.severe) {
    if (a.severe) return -1
    return 1
  }
  if (a instanceof CertError && a.endDate) {
    if (b instanceof CertError && b.endDate) {
      if (a.endDate - b.endDate) return a.endDate - b.endDate
      return 0
    }
    return 1
  }
  if (b instanceof CertError && b.endDate) return -1
  return 0
}

const checkOneCert = (certificate, days, now, chain) => {
  const validFrom = new Date(certificate.valid_from)
  const validTo = new Date(certificate.valid_to)
  const lifetimeDays = Math.floor((validTo - validFrom) / 86400000)
  var endDate = validTo
  var endReason = 'expiry'
  const pos = 'Certificate' + (chain ? ` ${chain + 1} in chain` : '')
  now = now || new Date()

  /* Check if the certificate has already expired. */

  if (validTo.getTime() <= now.getTime()) {
    throw new CertError(
      `${pos} expired on ${strftime('%d %b %Y', validTo)}!`,
      true, validTo)
  }

  /* Check if the certificate uses a deprecated algorithm.
     Requires converting the certificate to a node-forge one. */

  if (!chain) {
    const forgeCert = pki.certificateFromAsn1(
      asn1.fromDer(new ByteBuffer(certificate.raw)))
    const sigAlg = pki.oids[forgeCert.siginfo.algorithmOid]
    if (!sigAlg) {
      throw new CertError('Signature algorithm is unknown', false, validTo)
    }
    if (/md5|sha1(?!\d)/i.test(sigAlg)) {
      throw new CertError(`Signature algorithm is ${sigAlg}`, true, validTo)
    }
  }

  /* Check if the certificate has already become distrusted. */

  if (endDate.getTime() <= now.getTime()) {
    throw new CertError(
      `${pos} became distrusted on ${strftime('%d %b %Y', endDate)}!`,
      true, endDate)
  }

  /* Check if the certificate will expire or become distrusted soon. */

  const daysToLive = Math.floor((endDate - now) / 86400000)

  if (daysToLive < days) {
    throw new CertError(
      `${pos} ${endReason} date is ${strftime('%d %b %Y', endDate)}` +
      ` - ${daysToLive} day${daysToLive === 1 ? '' : 's'}`, false, endDate)
  }

  /* Check if the certificate has a too-long validity period. */

  if (!chain && validFrom.getTime() >= new Date('2018-03-01').getTime() &&
      lifetimeDays > 825) {
    throw new CertError(
      `Certificate lifetime of ${lifetimeDays} is too long`, true, endDate)
  }

  /* No problems found - return the certificate failure date. */

  return endDate
}

/** Check a certificate chain to see if it has any problems, such as expiring
  * soon or using a deprecated signature algorithm.
  *
  * @param {certificate} certificate - The certificate to check.
  * @param {integer} days - The number of days to consider 'soon'.
  * @param {Date} [now] - When to consider 'now' to be.
  * @returns {Date} - the date the certificate will fail.
  * @throws {CertError} There was a problem with a certificate.
  */
module.exports.checkCert = (certificate, days, now) => {
  let chain = 0
  let result
  let seenRootX1
  while (certificate) {
    /* We ignore the "DST Root CA X3" certificate if we have seen the
     * "ISRG Root X1" certificate, since LetsEncrypt are doing hacky
     * things which mean they're still using the former even though
     * it's expired.
     */
    if (certificate.serialNumber === '4001772137D4E942B8EE76AA3C640AB7') {
      seenRootX1 = true
    }
    if (!seenRootX1 || certificate.serialNumber !==
        '44AFB080D6A327BA893039862EF8406B') {
      let certResult
      try {
        certResult = checkOneCert(certificate, days, now, chain)
      } catch (e) {
        certResult = e
      }
      if (!result || compareResults(certResult, result) < 0) {
        result = certResult
      }
    }
    certificate = (certificate.issuerCertificate !== certificate)
      ? certificate.issuerCertificate : undefined
    chain += 1
  }
  if (result instanceof Date) return result
  throw result
}
