'use strict'

/* global describe, it */

const net = require('net')
const tls = require('tls')

const { createReader, createWriter } = require('awaitify-stream')
const byline = require('byline')

const { expect, getPEMCert, getPEMKey, makeCert } = require(
  './support/common')
const { connect } = require('../connect')

function startsslTimeout () {
  return new Promise((resolve, reject) => { setTimeout(resolve, 1.5 * 1000) })
}

async function startsslImap (readSocket, writeSocket) {
  await writeSocket.writeAsync('* OK Ready\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync('* CAPABILITY IMAP4rev1 IDLE STARTTLS\r\n')
  await writeSocket.writeAsync('a OK\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync('a OK Begin TLS now\r\n')
}

async function startsslImapNoSsl (readSocket, writeSocket) {
  await writeSocket.writeAsync('* OK Ready\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync('* CAPABILITY IMAP4rev1 IDLE\r\n')
  await writeSocket.writeAsync('a OK\r\n')
}

async function startsslSmtp (readSocket, writeSocket) {
  await writeSocket.writeAsync('220 foo ESMTP\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync(
    '250-foo\r\n250-STARTTLS\r\n250 PIPELINING\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync('220 2.0.0 Ready to start TLS\r\n')
}

async function startsslSmtpNoSsl (readSocket, writeSocket) {
  await writeSocket.writeAsync('220 foo ESMTP\r\n')
  await readSocket.readAsync()
  await writeSocket.writeAsync('250-foo\r\n250 PIPELINING\r\n')
}

describe('connect.js', function () {
  describe('connect', function () {
    this.slow(200)

    it('should be a function', function () {
      expect(connect).to.be.a('function')
    })

    const cert = makeCert()
    const pemCert = getPEMCert(cert)

    async function testConnect (protocol, startssl) {
      const server = net.createServer(async function (socket) {
        socket.setTimeout(3 * 1000, () => { socket.destroy() })
        if (startssl) {
          socket.setEncoding('binary')
          const readSocket = createReader(byline(socket))
          const writeSocket = createWriter(socket)
          await startssl(readSocket, writeSocket)
        }
        new tls.TLSSocket(socket, { // eslint-disable-line no-new
          cert: pemCert,
          handshakeTimeout: 2 * 1000,
          isServer: true,
          key: getPEMKey(),
          server
        })
      })
      server.listen()
      try {
        var connectCert = await connect(
          'localhost', server.address().port, protocol || 'none',
          1000, pemCert)
      } finally {
        server.close()
      }
      expect(connectCert).is.a('object').and.has.property('subject')
    }

    it('should connect to a socket and talk SSL', function () {
      return testConnect()
    })

    it('should notice a timeout', function () {
      this.slow(3 * 1000)
      return expect(testConnect('none', startsslTimeout))
        .to.be.rejectedWith(Error, /timeout/i)
    })

    it('should connect, talk IMAP, and then SSL', function () {
      return testConnect('imap', startsslImap)
    })

    it('should notice if IMAP doesn\'t support SSL', function () {
      return expect(testConnect('imap', startsslImapNoSsl))
        .to.be.rejectedWith(Error)
    })

    it('should connect, talk SMTP, and then SSL', function () {
      return testConnect('smtp', startsslSmtp)
    })

    it('should notice if SMTP doesn\'t support SSL', function () {
      return expect(testConnect('smtp', startsslSmtpNoSsl))
        .to.be.rejectedWith(Error)
    })
  })
})
