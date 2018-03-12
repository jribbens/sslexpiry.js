#!/usr/bin/env node
'use strict'

const fs = require('fs')

const { ArgumentParser, Const: { SUPPRESS } } = require('argparse')
const { createReader } = require('awaitify-stream')
const byline = require('byline')
const chalk = require('chalk')
const strftime = require('strftime')

const { CertError, checkCert } = require('./check-cert')
const { connect } = require('./connect')
const { version } = require('./package')

const sslexpiry = async () => {
  const parser = new ArgumentParser({
    description: 'SSL expiry checker'
  })
  parser.addArgument('servers', {
    nargs: '*',
    help: 'The servers to check'
  })
  parser.addArgument(['-d', '--days'], {
    defaultValue: 30,
    type: 'int',
    help: 'The number of days at which to warn of expiry'
  })
  parser.addArgument(['-f', '--from-file'], {
    action: 'append',
    defaultValue: [],
    metavar: 'FILENAME',
    help: 'Read the servers to check from the specified file'
  })
  parser.addArgument(['-t', '--timeout'], {
    defaultValue: 30,
    type: 'int',
    metavar: 'SECONDS',
    help: 'The number of seconds to allow for server response'
  })
  parser.addArgument(['-v', '--verbose'], {
    action: 'count',
    help: 'Display verbose output'
  })
  parser.addArgument(['-V', '--version'], {
    action: 'version',
    version,
    defaultValue: SUPPRESS,
    help: 'Show program\'s version number and exit.'
  })

  const args = parser.parseArgs()
  const servers = args.servers.slice()
  const results = {}

  for (let filename of args.from_file) {
    const serverFile = fs.createReadStream(filename, 'utf8')
    const lineStream = createReader(byline(serverFile))
    let line
    do {
      line = await lineStream.readAsync()
      if (line) line = line.split('#', 1)[0].trim()
      if (line) servers.push(line)
    } while (line !== null)
  }

  const promises = []
  let longest = 1
  for (let server of servers) {
    let servername, protocol, port
    ;[ servername, protocol ] = server.split('/', 2)
    ;[ servername, port ] = servername.split(':', 2)
    promises.push((async () => {
      try {
        const certificate = await connect(
          servername, port, protocol, args.timeout * 1000)
        results[server] = checkCert(certificate, args.days)
        if (args.verbose) {
          if (server.length > longest) longest = server.length
        }
      } catch (e) {
        results[server] = e
        process.exitCode = 74
        if (server.length > longest) longest = server.length
      }
    })())
  }
  await Promise.all(promises)

  servers.sort((keyA, keyB) => {
    const a = results[keyA]
    const b = results[keyB]
    if (a instanceof Date) {
      if (b instanceof Date) return a - b
      return 1
    }
    if (b instanceof Date) return -1
    if (a instanceof CertError && a.endDate) {
      if (b instanceof CertError && b.endDate) return a.endDate - b.endDate
      return 1
    }
    if (b instanceof CertError && b.endDate) return -1
    return keyA < keyB ? -1 : 1
  })

  for (let server of servers) {
    let result = results[server]
    if (result instanceof Date) {
      if (args.verbose) {
        console.log(
          server.padEnd(longest),
          strftime('%d %b %Y', result))
      }
    } else {
      if (result instanceof CertError && !result.severe) {
        console.log(chalk.yellow(server.padEnd(longest), result.message))
      } else if (result instanceof Error) {
        console.log(chalk.red(server.padEnd(longest), result.message))
      } else {
        console.log(server.padEnd(longest), result)
      }
    }
  }
}

;(async () => {
  try {
    await sslexpiry()
  } catch (e) {
    console.log(e)
    process.exitCode = 1
  }
})()
