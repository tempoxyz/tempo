// Usage: node compile.cjs /path/to/solc/package
// Install solc@0.8.30 outside the repository; emit an artifact on stdout.
const fs = require('node:fs');
const path = require('node:path');
const solc = require(path.resolve(process.argv[2]));
if (!solc.version().startsWith('0.8.30+')) throw Error('Expected solc 0.8.30');
const source = fs.readFileSync(path.join(__dirname, 'GasCalibration.sol'), 'utf8');
const settings = {
  optimizer: { enabled: true, runs: 200 },
  evmVersion: 'cancun',
  outputSelection: { '*': { '*': ['abi', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers'] } },
};
const result = JSON.parse(solc.compile(JSON.stringify({
  language: 'Solidity', sources: { 'GasCalibration.sol': { content: source } }, settings,
})));
for (const error of result.errors || []) {
  if (error.severity === 'error') throw Error(error.formattedMessage);
  process.stderr.write(error.formattedMessage);
}
const contract = result.contracts['GasCalibration.sol'].GasCalibration;
process.stdout.write(JSON.stringify({
  compiler: solc.version(), settings, abi: contract.abi,
  bytecode: { object: '0x' + contract.evm.bytecode.object },
  deployedBytecode: { object: '0x' + contract.evm.deployedBytecode.object },
  methodIdentifiers: contract.evm.methodIdentifiers,
}, null, 2) + '\n');
