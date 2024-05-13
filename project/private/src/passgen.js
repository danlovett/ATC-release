const { Command } = require('commander')
const createPassword = require('./createPassword')

const program = new Command()

program
  .option('-l, --length <number>', 'length of password', '15')
  .option('-s, --save', 'save password to passwords.txt')
  .option('-nn, --no-numbers', 'remove numbers')
  .option('-ns, --no-symbols', 'remove symbols')
  .parse()

const { length, save, numbers, symbols } = program.opts()

// Get generated password
const generatedPassword = createPassword(length, numbers, symbols)

module.exports = generatedPassword