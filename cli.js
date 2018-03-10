#!/usr/bin/env node
'use strict'

const fs = require('fs')

const { createReader } = require('awaitify-stream')
const byline = require('byline')
const chalk = require('chalk')
const program = require('commander')
const strftime = require('strftime')

const { CertError, checkCert } = require('./check-cert')
const { connect } = require('./connect')
const { version } = require('./package')

const sslexpiry = async () => {
  program
    .version(version)
    .description('SSL expiry checker')
    .option('-d, --days [days]',
            'The number of days at which to warn of expiry', parseInt, 30)
    .option('-f, --from-file [filename]',
            'Read the servers to check from the specified file')
    .option('-t, --timeout [seconds]',
            'The number of seconds to allow for server response',
            parseInt, 30)
    .option('-v, --verbose', 'Display verbose output')
    .parse(process.argv)

  const servers = program.args.slice()
  const results = {}

  if (program.fromFile) {
    const serverFile = fs.createReadStream(program.fromFile)
    serverFile.setEncoding('utf8')
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
          servername, port, protocol, program.timeout * 1000)
        results[server] = checkCert(certificate, program.days)
        if (program.verbose) {
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
      if (program.verbose) {
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
