'use strict'

/* global describe, it */

const { expect } = require('chai')
const index = require('../')
const packageJson = require('../package')

describe('sslexpiry', function () {
  it('should export CertError', function () {
    expect(index.CertError).to.be.a('function')
    expect(new index.CertError()).to.be.an.instanceof(Error)
  })

  it('should export checkCert', function () {
    expect(index.checkCert).to.be.a('function')
  })

  it('should export connect', function () {
    expect(index.connect).to.be.a('function')
  })

  it('should export version', function () {
    expect(index.version).to.equal(packageJson.version)
  })
})
