'use strict'

/* global afterEach, beforeEach, describe, it */

const chalk = require('chalk')
const path = require('path')
const strftime = require('strftime')

const { CertError } = require('../check-cert')
const cli = require('../cli')
const { version } = require('../package')

const { expect } = require('./support/common')

const DAYS = 86400 * 1000

describe('cli.js', function () {
  let chalkLevel
  const connects = []
  const now = new Date()
  const date = new Date(+now + 60 * DAYS)
  const sDate = strftime('%d %b %Y', date)
  let checkDays
  let result

  // mocks

  function checkCert (certificate, days) {
    const response = {
      badsig: new CertError('badsig', true, date),
      error: new Error('error'),
      expired: new CertError('expired', true, new Date(+now - 7 * DAYS)),
      expiring: new CertError('expiring', false, new Date(+now + 7 * DAYS))
    }[certificate._name.split(',', 1)[0]] || date
    checkDays = days
    if (response instanceof Error) throw response
    return response
  }

  function connect (servername, port, protocol, timeout) {
    const name = '' + servername + ',' + port + ',' + protocol + ',' + timeout
    connects.push(name)
    return { _name: name, serialNumber: '01deadBEEF01' }
  }

  function output (message) { result += message.trimRight() + '\n' }

  function sslexpiry (...argv) {
    checkDays = undefined
    connects.length = 0
    result = ''
    process.exitCode = 0
    return cli.sslexpiry(argv, {
      checkCert,
      connect,
      debug: true,
      output
    })
  }

  beforeEach(function () {
    chalkLevel = chalk.level
    chalk.level = 0
  })

  afterEach(function () {
    chalk.level = chalkLevel
  })

  it('should do nothing with no arguments', async function () {
    await sslexpiry()
    expect(result).to.equal('')
  })

  it('should output the version with -V', async function () {
    await sslexpiry('-V')
    expect(result).to.equal(version + '\n')
  })

  it('should output help with -h', async function () {
    await sslexpiry('-h')
    expect(result).to.match(/^usage:/)
  })

  it('should default to 30-day expiry', async function () {
    await sslexpiry('server1')
    expect(checkDays).to.equal(30)
  })

  it('should accept an expiry with -d', async function () {
    await sslexpiry('-d', '40', 'server1')
    expect(checkDays).to.equal(40)
  })

  it('should accept an expiry with --days', async function () {
    await sslexpiry('--days', '50', 'server1')
    expect(checkDays).to.equal(50)
  })

  it('should default to 30-second timeout', async function () {
    await sslexpiry('server1')
    expect(connects).to.have.lengthOf(1)
    expect(connects[0]).to.match(/,30000$/)
  })

  it('should accept a timeout with -t', async function () {
    await sslexpiry('-t', '10', 'server1')
    expect(connects).to.have.lengthOf(1)
    expect(connects[0]).to.match(/,10000$/)
  })

  it('should accept a timeout with --timeout', async function () {
    await sslexpiry('--timeout', '25', 'server1')
    expect(connects).to.have.lengthOf(1)
    expect(connects[0]).to.match(/,25000$/)
  })

  it('should process server arguments', async function () {
    await sslexpiry('server1', 'server2')
    expect(connects).to.deep.equal([
      'server1,undefined,undefined,30000',
      'server2,undefined,undefined,30000'
    ])
    expect(result).to.equal('')
  })

  it('should understand server:port', async function () {
    await sslexpiry('server1:port')
    expect(connects).to.deep.equal([
      'server1,port,undefined,30000'
    ])
  })

  it('should understand server/protocol', async function () {
    await sslexpiry('server1/protocol')
    expect(connects).to.deep.equal([
      'server1,undefined,protocol,30000'
    ])
  })

  it('should understand server:port/protocol', async function () {
    await sslexpiry('server1:port/protocol')
    expect(connects).to.deep.equal([
      'server1,port,protocol,30000'
    ])
  })

  it('should ignore \'!\' prefixed to server name', async function () {
    await sslexpiry('!server1')
    expect(connects).to.deep.equal([
      'server1,undefined,undefined,30000'
    ])
  })

  it('should do nothing when no issues', async function () {
    await sslexpiry('server1')
    expect(result).to.equal('')
    expect(process.exitCode).to.be.oneOf([undefined, 0])
  })

  it('should set exit code when issues found', async function () {
    await sslexpiry('expired')
    expect(process.exitCode).to.equal(74)
  })

  it('should not set exit code with --exit-zero', async function () {
    await sslexpiry('--exit-zero', 'expired')
    expect(process.exitCode).to.equal(0)
  })

  it('should output messages when issues found', async function () {
    await sslexpiry('badsig', 'expiring', 'expired')
    expect(result).to.match(/^badsig +badsig\n/m)
      .and.to.match(/^expiring +expiring\n/m)
      .and.to.match(/^expired +expired\n/m)
  })

  it('should output dates with -v', async function () {
    await sslexpiry('-v', 'server1', 'server2')
    expect(connects).to.deep.equal([
      'server1,undefined,undefined,30000',
      'server2,undefined,undefined,30000'
    ])
    expect(result).to.equal(`server1 ${sDate}\nserver2 ${sDate}\n`)
  })

  it('should order equal dates by server name', async function () {
    await sslexpiry('-v', 'server2', 'server1')
    expect(result).to.equal(`server1 ${sDate}\nserver2 ${sDate}\n`)
  })

  it('should order expiring before ok', async function () {
    await sslexpiry('-v', 'server1', 'expiring', 'server2')
    expect(result).to.equal(
      `expiring expiring\nserver1  ${sDate}\nserver2  ${sDate}\n`)
    await sslexpiry('-v', 'server1', 'server2', 'expiring')
    expect(result).to.equal(
      `expiring expiring\nserver1  ${sDate}\nserver2  ${sDate}\n`)
  })

  it('should order expired before expiring', async function () {
    await sslexpiry('-v', 'server1', 'expired', 'expiring', 'server2')
    expect(result).to.equal(
      'expired  expired\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
    await sslexpiry('-v', 'server1', 'expiring', 'server2', 'expired')
    expect(result).to.equal(
      'expired  expired\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
  })

  it('should order severe before non-severe', async function () {
    await sslexpiry('-v', 'server1', 'expiring', 'badsig', 'server2')
    expect(result).to.equal(
      'badsig   badsig\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
    await sslexpiry('-v', 'server1', 'expiring', 'server2', 'badsig')
    expect(result).to.equal(
      'badsig   badsig\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
  })

  it('should order errors before everything', async function () {
    await sslexpiry('-v', 'server1', 'error', 'expiring', 'badsig', 'server2')
    expect(result).to.equal(
      'error    error\nbadsig   badsig\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
    await sslexpiry('-v', 'server1', 'expiring', 'server2', 'badsig', 'error')
    expect(result).to.equal(
      'error    error\nbadsig   badsig\nexpiring expiring\n' +
      `server1  ${sDate}\nserver2  ${sDate}\n`)
  })

  it('should read from config files', async function () {
    await sslexpiry('-f', path.join(__dirname, 'config.txt'), 'error')
    expect(connects).to.deep.equal([
      'error,undefined,undefined,30000',
      'server1,undefined,undefined,30000',
      'server2,port,undefined,30000',
      'server1,undefined,protocol,30000',
      'server1,port,protocol,30000'
    ])
  })

  it('should accept multiple config files', async function () {
    await sslexpiry(
      '-f', path.join(__dirname, 'config.txt'),
      '--from-file', path.join(__dirname, 'config.txt'), 'error')
    expect(connects).to.deep.equal([
      'error,undefined,undefined,30000',
      'server1,undefined,undefined,30000',
      'server2,port,undefined,30000',
      'server1,undefined,protocol,30000',
      'server1,port,protocol,30000',
      'server1,undefined,undefined,30000',
      'server2,port,undefined,30000',
      'server1,undefined,protocol,30000',
      'server1,port,protocol,30000'
    ])
  })

  it('should check bad-serials files', async function () {
    await sslexpiry(
      '-b', path.join(__dirname, 'bad-serials.txt'),
      'server1')
    expect(result).to.equal('server1 Serial number is on the bad list\n')
  })
})
