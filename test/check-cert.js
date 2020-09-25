'use strict'

/* global describe, it, beforeEach */

const { expect, getNodeCert, makeCert } = require('./support/common')
const { CertError, checkCert } = require('../check-cert')

describe('check-cert.js', function () {
  describe('CertError', function () {
    it('should be an instance of Error', function () {
      expect(new CertError()).to.be.an.instanceof(Error)
    })
    it('should have an \'endDate\' property', function () {
      expect(new CertError('test', false, new Date()))
        .property('endDate').to.be.instanceof(Date)
    })
    it('should have a \'message\' property', function () {
      expect(new CertError('xyzzy')).property('message', 'xyzzy')
    })
    it('should have a \'severe\' property', function () {
      expect(new CertError()).property('severe', false)
    })
  })

  describe('checkCert', function () {
    var cert
    var issuer
    var now

    beforeEach(function () {
      issuer = undefined
      now = undefined
    })

    function callCheckCert () {
      return checkCert(
        issuer ? getNodeCert(cert, issuer) : getNodeCert(cert), 30, now)
    }

    it('should be a function', function () {
      expect(checkCert).to.be.a('function')
    })

    it('should accept a good certificate', function () {
      cert = makeCert()
      expect(callCheckCert()).to.be.an.instanceof(Date)
        .sameMoment(cert.validity.notAfter)
    })

    it('should reject an expired certificate', function () {
      cert = makeCert({ notAfter: -1 })
      expect(callCheckCert).to.throw(CertError, /expired/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should reject a certificate that expires soon', function () {
      cert = makeCert({ notAfter: 3 })
      expect(callCheckCert).to.throw(CertError, /expir/i)
        .to.include({ severe: false })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should reject an SHA1 signature', function () {
      cert = makeCert({ signature: 'sha1' })
      expect(callCheckCert).to.throw(CertError, /sha1/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should reject an MD5 signature', function () {
      cert = makeCert({ signature: 'md5' })
      expect(callCheckCert).to.throw(CertError, /md5/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should accept older 826-day certificate', function () {
      cert = makeCert({
        notBefore: new Date('2017-03-01'),
        notAfter: new Date('2019-06-05')
      })
      now = new Date('2018-10-01')
      expect(callCheckCert()).to.be.an.instanceof(Date)
        .sameMoment(cert.validity.notAfter)
    })

    it('should reject newer 826-day certificate', function () {
      cert = makeCert({
        notBefore: new Date('2018-03-01'),
        notAfter: new Date('2020-06-04')
      })
      now = new Date('2018-10-01')
      expect(callCheckCert).to.throw(CertError, /too long/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should return the earliest expiry in the chain', function () {
      cert = makeCert({ notAfter: 60 })
      issuer = makeCert({ notAfter: 40 })
      expect(callCheckCert()).to.be.an.instanceof(Date)
        .sameMoment(issuer.validity.notAfter)
      cert = makeCert({ notAfter: 40 })
      issuer = makeCert({ notAfter: 60 })
      expect(callCheckCert()).to.be.an.instanceof(Date)
        .sameMoment(cert.validity.notAfter)
    })

    it('should reject the expired certificate in a chain #1', function () {
      cert = makeCert({ notAfter: -1 })
      issuer = makeCert()
      expect(callCheckCert).to.throw(CertError, /expired/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should reject the expired certificate in a chain #2', function () {
      cert = makeCert()
      issuer = makeCert({ notAfter: -1 })
      expect(callCheckCert).to.throw(CertError, /expired/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(issuer.validity.notAfter)
    })

    it('should reject the oldest expired certificate #1', function () {
      cert = makeCert({ notAfter: -2 })
      issuer = makeCert({ notAfter: -1 })
      expect(callCheckCert).to.throw(CertError, /expired/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(cert.validity.notAfter)
    })

    it('should reject the oldest expired certificate #2', function () {
      cert = makeCert({ notAfter: -1 })
      issuer = makeCert({ notAfter: -2 })
      expect(callCheckCert).to.throw(CertError, /expired/i)
        .to.include({ severe: true })
        .with.property('endDate').sameMoment(issuer.validity.notAfter)
    })
  })
})
