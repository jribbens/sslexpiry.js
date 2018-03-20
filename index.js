'use strict'

const { CertError, checkCert } = require('./check-cert')
const { connect } = require('./connect')
const { version } = require('./package')

module.exports.CertError = CertError
module.exports.checkCert = checkCert
module.exports.connect = connect
module.exports.version = version

if (require.main === module) require('./cli.js').sslexpiry()
