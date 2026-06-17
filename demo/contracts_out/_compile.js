
const solc = require('solc');
const fs   = require('fs');
const source = fs.readFileSync('contracts/VotingContract.sol', 'utf8');
const input  = {
  language: 'Solidity',
  sources:  { 'VotingContract.sol': { content: source } },
  settings: {
    evmVersion: 'paris',
    optimizer:  { enabled: true, runs: 200 },
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } }
  }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors || []).filter(e => e.severity === 'error');
if (errors.length > 0) {
  process.stderr.write(JSON.stringify(errors));
  process.exit(1);
}
const c = output.contracts['VotingContract.sol']['VotingContract'];
fs.mkdirSync('contracts_out', { recursive: true });
fs.writeFileSync('contracts_out/VotingContract.abi', JSON.stringify(c.abi));
fs.writeFileSync('contracts_out/VotingContract.bin', c.evm.bytecode.object);
console.log('OK');
