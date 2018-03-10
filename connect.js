'use strict'

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

module.exports.connect = async (servername, port, protocol, timeout) => {
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
        var tlsSocket = tls.connect({socket, servername}, () => {
          if (!tlsSocket.authorized) {
            reject(new Error(tlsSocket.authorizationError))
          } else {
            var certificate = tlsSocket.getPeerCertificate()
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
