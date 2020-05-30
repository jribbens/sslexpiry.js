#!/usr/bin/env node
'use strict'

const fs = require('fs')

const { ArgumentParser, Const: { SUPPRESS } } = require('argparse')
const { createReader } = require('awaitify-stream')
const byline = require('byline')
const chalk = require('chalk')
const strftime = require('strftime')

const { CertError, compareResults } = require('./check-cert')
const { version } = require('./package')

const padEnd = (string, targetLength) => {
  while (string.length < targetLength) string += ' '
  return string
}

const sslexpiry = async (argv,
  { debug = false, checkCert, connect, output = console.log } = {}) => {
  checkCert = checkCert || require('./check-cert').checkCert
  connect = connect || require('./connect').connect

  const parser = new ArgumentParser({
    debug,
    description: 'SSL expiry checker',
    prog: 'sslexpiry'
  })
  if (debug) {
    parser.exit = function (status, message) { this._printMessage(message) }
    if (output) {
      parser._printMessage = (message) => { message && output('' + message) }
    }
  }
  parser.addArgument('servers', {
    metavar: 'SERVER',
    nargs: '*',
    help: 'Check the specified server.'
  })
  parser.addArgument(['-b', '--bad-serials'], {
    action: 'append',
    defaultValue: [],
    metavar: 'FILENAME',
    help: 'Check the certificate serial numbers against the specified file.'
  })
  parser.addArgument(['-d', '--days'], {
    defaultValue: 30,
    type: 'int',
    help: 'The number of days at which to warn of expiry. (default=30)'
  })
  parser.addArgument(['-f', '--from-file'], {
    action: 'append',
    defaultValue: [],
    metavar: 'FILENAME',
    help: 'Read the servers to check from the specified file.'
  })
  parser.addArgument(['-i', '--ignore-chain'], {
    action: 'storeTrue',
    help: 'Don\'t check other certificates in the chain'
  })
  parser.addArgument(['-t', '--timeout'], {
    defaultValue: 30,
    type: 'int',
    metavar: 'SECONDS',
    help: 'The number of seconds to allow for server response. (default=30)'
  })
  parser.addArgument(['-v', '--verbose'], {
    action: 'count',
    help: 'Display verbose output.'
  })
  parser.addArgument(['-V', '--version'], {
    action: 'version',
    version,
    defaultValue: SUPPRESS,
    help: 'Show program\'s version number and exit.'
  })
  parser.addArgument(['-z', '--exit-zero'], {
    action: 'storeTrue',
    help: 'Always return a process exit code of zero.'
  })

  const args = parser.parseArgs(argv)
  const servers = args.servers.slice()
  const badSerials = {}
  const results = {}
  const serials = {}

  for (const filename of args.from_file) {
    const serverFile = fs.createReadStream(filename, 'utf8')
    const lineStream = createReader(byline(serverFile))
    let line
    do {
      line = await lineStream.readAsync()
      if (line) line = line.split('#', 1)[0].trim()
      if (line) servers.push(line)
    } while (line !== null)
  }

  for (const filename of args.bad_serials) {
    const serialFile = fs.createReadStream(filename, 'utf8')
    const lineStream = createReader(byline(serialFile))
    let line
    do {
      line = await lineStream.readAsync()
      if (line) line = line.split('#', 1)[0].trim()
      if (line) badSerials[line.toLowerCase()] = true
    } while (line !== null)
  }

  const promises = []
  let longest = 1
  for (const server of servers) {
    let servername, protocol, port
    ;[servername, protocol] = server.split('/', 2)
    ;[servername, port] = servername.split(':', 2)
    if (servername.charAt(0) === '!') servername = servername.substr(1)
    promises.push((async () => {
      try {
        const certificate = await connect(
          servername, port, protocol, args.timeout * 1000)
        serials[server] = certificate.serialNumber
        if (badSerials[certificate.serialNumber.toLowerCase()]) {
          throw new CertError('Serial number is on the bad list', true)
        } else {
          if (args.ignore_chain) delete certificate.issuerCertificate
          results[server] = checkCert(certificate, args.days)
        }
        if (args.verbose) {
          if (server.length > longest) longest = server.length
        }
      } catch (e) {
        results[server] = e
        if (!args.exit_zero) process.exitCode = 74
        if (server.length > longest) longest = server.length
      }
    })())
  }
  await Promise.all(promises)

  servers.sort((keyA, keyB) =>
    compareResults(results[keyA], results[keyB]) || (keyA < keyB ? -1 : 1))

  for (const server of servers) {
    const result = results[server]
    const serial = (args.verbose > 1)
      ? (' ' + padEnd(serials[server], 36)) : ''
    if (result instanceof Date) {
      if (args.verbose) {
        output(padEnd(server, longest) + serial + ' ' +
               strftime('%d %b %Y', result))
      }
    } else {
      if (result instanceof CertError && !result.severe) {
        output(chalk.yellow(padEnd(server, longest) + serial + ' ' +
               result.message))
      } else if (result instanceof Error) {
        output(chalk.red(padEnd(server, longest) + serial + ' ' +
               result.message))
      } else {
        output(padEnd(server, longest) + serial + ' ' + result)
      }
    }
  }
}

module.exports.sslexpiry = sslexpiry

if (require.main === module) {
  ;(async () => {
    try {
      await sslexpiry()
    } catch (e) {
      console.log(e)
      process.exitCode = 1
    }
  })()
}
