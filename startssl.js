const { createReader, createWriter } = require('awaitify-stream')
const byline = require('byline')

const none = (readSocket, writeSocket) => {}

const smtp = async (readSocket, writeSocket) => {
  var found
  var line

  line = await readSocket.readAsync()
  if (!line.startsWith('220 ')) {
    throw new Error(`Unexpected SMTP greeting: ${line}`)
  }
  await writeSocket.writeAsync('EHLO mail.example.com\r\n')
  line = await readSocket.readAsync()
  if (!line.startsWith('250-')) {
    throw new Error(`Unexpected EHLO response: ${line}`)
  }
  do {
    line = await readSocket.readAsync()
    if (line.startsWith('250-STARTTLS')) found = true
  } while (line.startsWith('250-'))
  if (!line.startsWith('250 ')) {
    throw new Error(`Unexpected EHLO response: ${line}`)
  }
  if (!found) throw new Error('SMTP server does not support STARTTLS')
  await writeSocket.writeAsync('STARTTLS\r\n')
  line = await readSocket.readAsync()
  if (!line.startsWith('220 ')) {
    throw new Error(`Unexpected STARTTLS response: ${line}`)
  }
}

const imap = async (readSocket, writeSocket) => {
  var line

  line = await readSocket.readAsync()
  if (!line.startsWith('* OK')) {
    throw new Error(`Unexpected IMAP greeting: ${line}`)
  }
  await writeSocket.writeAsync('a CAPABILITY\r\n')
  line = await readSocket.readAsync()
  if (!line.startsWith('* CAPABILITY')) {
    throw new Error(`Unexpected IMAP CAPABILITY response: ${line}`)
  }
  if (!/\bSTARTTLS\b/.test(line)) {
    throw new Error('IMAP server does not support STARTTLS')
  }
  line = await readSocket.readAsync()
  if (!line.startsWith('a OK')) {
    throw new Error(`Unexpected IMAP CAPABILITY response: ${line}`)
  }
  await writeSocket.writeAsync('a STARTTLS\r\n')
  line = await readSocket.readAsync()
  if (!line.startsWith('a OK')) {
    throw new Error(`Unexpected IMAP STARTTLS response: ${line}`)
  }
}

module.exports.startssl = async (socket, protocol) => {
  socket.setEncoding('binary')
  const readSocket = createReader(byline(socket))
  const writeSocket = createWriter(socket)
  const handler = { none, imap, smtp }[protocol || 'none']
  if (!handler) throw new Error(`Unknown protocol ${protocol}`)
  return handler(readSocket, writeSocket)
}
