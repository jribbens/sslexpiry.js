'use strict'

/**
  * Connect module. Provides a function to fetch a TLS certificate from
  * a network server.
  * @module connect
  */

const net = require('net')
const tls = require('tls')
const { startssl } = require('./startssl')

const getPort = (port) => {
  if (port === undefined || port === '') return { port: 443 }
  if (typeof port === 'number') return { port }
  if (/^[0-9]+$/.test(port)) return { port: parseInt(port) }
  return {
    https: { port: 443 },
    imap: { port: 143, protocol: 'imap' },
    imaps: { port: 993 },
    pop3s: { port: 995 },
    smtp: { port: 25, protocol: 'smtp' },
    smtps: { port: 465 },
    submission: { port: 587, protocol: 'smtp' }
  }[port]
}

/**
  * Connect to a network service, optionally perform some sort of STARTSSL
  * procedure, then negotiate TLS and return the server's certificate.
  *
  * @async
  * @param {string} servername - The DNS name to connect to.
  * @param {(string|integer)} [port=443] - The TCP port to connect to.
  * @param {string} [protocol] - The STARTTLS protocol to use. Defaults to
  *   'none', except if <port> is 'smtp', 'submission' or 'imap'.
  * @param {integer} [timeout] - The number of milliseconds to wait.
  * @param {object} [ca] - secureContext 'ca' parameter.
  * @returns {certificate} The server's certificate.
  */

module.exports.connect = (servername, port, protocol, timeout, ca) => {
  const portInfo = getPort(port)
  if (!portInfo) throw new Error(`Unknown port ${port}`)
  if (!protocol && portInfo.protocol) protocol = portInfo.protocol
  return new Promise((resolve, reject) => {
    var socket
    try {
      socket = net.createConnection(portInfo.port, servername, async () => {
        try {
          await startssl(socket, protocol)
        } catch (e) {
          reject(e)
          socket.destroy()
          return
        }
        var tlsSocket = tls.connect({ ca, servername, socket }, () => {
          if (!tlsSocket.authorized) {
            reject(new Error(tlsSocket.authorizationError))
          } else {
            var certificate = tlsSocket.getPeerCertificate(true)
            resolve(certificate)
          }
          socket.destroy()
        })
        tlsSocket.on('error', (e) => {
          reject(e)
          socket.destroy()
        })
      })
      if (timeout) {
        socket.setTimeout(timeout, () => {
          reject(new Error('Timeout connecting to server'))
          socket.destroy()
        })
      }
      socket.on('error', (e) => {
        reject(e)
        socket.destroy()
      })
    } catch (e) {
      reject(e)
      if (socket) socket.destroy()
    }
  })
}
