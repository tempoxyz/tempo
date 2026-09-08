// NODE_PATH=<directory containing solc@0.8.30>/node_modules node build.cjs
const fs = require('node:fs');
const path = require('node:path');
const solc = require('solc');
if (!solc.version().startsWith('0.8.30+')) throw new Error('Use solc 0.8.30');
const input = {
  language: 'Solidity',
  sources: { 'PortalFixture.sol': { content: fs.readFileSync(path.join(__dirname, 'PortalFixture.sol'), 'utf8') } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
  },
};
const result = JSON.parse(solc.compile(JSON.stringify(input)));
for (const error of result.errors ?? []) {
  if (error.severity === 'error') throw new Error(error.formattedMessage);
}
const contracts = result.contracts['PortalFixture.sol'];
fs.writeFileSync(path.join(__dirname, 'PortalFixture.json'), JSON.stringify({
  abi: contracts.PortalFixture.abi,
  bytecode: { object: '0x' + contracts.PortalFixture.evm.bytecode.object },
}, null, 2) + '\n');
fs.writeFileSync(path.join(__dirname, 'portal.abi.json'), JSON.stringify(contracts.IPortal.abi, null, 2) + '\n');
