import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { ethers } from 'ethers';
import { zkAddress } from './oidc.mjs';
import { PUBLISHER, KEYCHAIN, USD, hex32, quantity, transactionFields, transactionDigest, signedTransaction, zkSignature, keyAuthorization, accessKeySignature } from './protocol.mjs';

const [artifact, rpc = 'http://127.0.0.1:8545'] = process.argv.slice(2);
if (!artifact || !/^http:\/\/(127\.0\.0\.1|localhost):\d+\/?$/.test(rpc)) throw new Error('Supply a fixture proof and loopback RPC; this test uses publicly known development keys');
const provider = new ethers.JsonRpcProvider(rpc, undefined, { cacheTimeout: -1 });
assert.equal((await provider.getNetwork()).chainId, 1337n);
const fixture = JSON.parse(await readFile(artifact, 'utf8'));
const { input, proof } = fixture;
const mnemonic = 'test test test test test test test test test test test junk';
const root = new ethers.NonceManager(ethers.HDNodeWallet.fromPhrase(mnemonic).connect(provider));
const device = ethers.HDNodeWallet.fromPhrase(mnemonic, undefined, "m/44'/60'/0'/0/1");
assert.equal(BigInt(device.address).toString(), input.commit_a);
const publisher = new ethers.Contract(PUBLISHER, [
  'function createPublisher(bytes32 salt,address owner,(bytes32 issuer,bytes32[] keyHashes)[] initialKeys) returns(bytes32)',
  'function revokeKey(bytes32 publisherId,bytes32 issuer,bytes32 keyHash)',
  'function isKeyActive(bytes32 publisherId,bytes32 issuer,bytes32 keyHash) view returns(bool)',
], root);
const tokenInterface = new ethers.Interface(['function transfer(address to,uint256 amount) returns(bool)','function balanceOf(address account) view returns(uint256)']);
const token = new ethers.Contract(USD, tokenInterface, root);
const salt = ethers.hexlify(randomBytes(32));
const owner = await root.getAddress();
const publisherId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address','bytes32'],[owner,salt]));
const account = zkAddress(publisherId, input.issuer, input.address_seed);
const recipient = ethers.Wallet.createRandom().address;
async function receipt(transaction, label) {
  const result = await transaction.wait();
  assert.equal(result.status, 1, label);
  console.log(JSON.stringify({ label, hash: result.hash, block: result.blockNumber, status: result.status }));
  return result;
}
async function tempoReceipt(raw, label) {
  const hash = await provider.send('eth_sendRawTransaction',[raw]);
  const deadline = Date.now()+120000;
  while (Date.now() < deadline) {
    const result = await provider.send('eth_getTransactionReceipt',[hash]);
    if (result) {
      assert.equal(BigInt(result.status),1n,label);
      console.log(JSON.stringify({ label,hash,block:Number(BigInt(result.blockNumber)),status:1 }));
      return result;
    }
    await new Promise(resolve => setTimeout(resolve,1000));
  }
  throw new Error(`Receipt timeout for ${label}: ${hash}`);
}
await receipt(await publisher.createPublisher(salt,owner,[[hex32(input.issuer),[hex32(input.key_hash)]]]), 'publish RSA issuer key');
assert.equal(await publisher.isKeyActive(publisherId,hex32(input.issuer),hex32(input.key_hash)), true);
await receipt(await token.transfer(account,100000n), 'fund OIDC account');
const payment = { to: USD, data: tokenInterface.encodeFunctionData('transfer',[recipient,1000n]) };
const auth = keyAuthorization(device,input,publisherId,proof);
const firstFields = transactionFields({ calls:[payment], keyAuthorization:auth, validBefore: input.commit_b });
const firstRaw = signedTransaction(firstFields,zkSignature({ input,publisherId,proof,digest:transactionDigest(firstFields),wallet:device }));
await tempoReceipt(firstRaw, 'RS256 proof-authorized 0x06 payment and device-key installation');
const secondFields = transactionFields({ calls:[payment], nonce:1 });
const secondRaw = signedTransaction(secondFields,accessKeySignature(secondFields,account,device));
await tempoReceipt(secondRaw, 'device-key payment without another proof');
assert.equal(await token.balanceOf(recipient), 2000n);
async function rejected(raw,label) {
  try { await provider.send('eth_sendRawTransaction',[raw]); }
  catch (error) {
    const detail = `${error.shortMessage ?? ''} ${error.error?.message ?? ''} ${JSON.stringify(error.info?.error ?? {})}`;
    if (!/nonce|already known|ZK signature|revok|expired|key|signature/i.test(detail)) throw error;
    console.log(`Rejected: ${label}`); return;
  }
  throw new Error(`Expected rejection: ${label}`);
}
await rejected(firstRaw,'replay of proof-authorized transaction');
const thirdFields = transactionFields({ calls:[payment], nonce:2 });
const changed = { ...input, commit_b:(BigInt(input.commit_b)-1n).toString() };
await rejected(signedTransaction(thirdFields,zkSignature({ input:changed,publisherId,proof,digest:transactionDigest(thirdFields),wallet:device })), 'proof nonce/expiry rebinding');
await rejected(signedTransaction(thirdFields,zkSignature({ input:{...input,commit_b:'1'},publisherId,proof,digest:transactionDigest(thirdFields),wallet:device })), 'expired OIDC signature');
const wrongProof = structuredClone(proof); wrongProof.pi_c[0] = '1';
await rejected(signedTransaction(thirdFields,zkSignature({ input,publisherId,proof:wrongProof,digest:transactionDigest(thirdFields),wallet:device })), 'invalid proof');
const keychain = new ethers.Interface(['function revokeKey(address keyId)']);
const revokeFields = transactionFields({ calls:[{to:KEYCHAIN,data:keychain.encodeFunctionData('revokeKey',[device.address])}], nonce:2 });
await tempoReceipt(signedTransaction(revokeFields,zkSignature({ input,publisherId,proof,digest:transactionDigest(revokeFields),wallet:device })), 'OIDC root revokes device key');
const revokedFields = transactionFields({ calls:[payment], nonce:3 });
await rejected(signedTransaction(revokedFields,accessKeySignature(revokedFields,account,device)), 'revoked device key');
await receipt(await publisher.revokeKey(publisherId,hex32(input.issuer),hex32(input.key_hash)), 'publisher revokes RSA issuer key');
assert.equal(await publisher.isKeyActive(publisherId,hex32(input.issuer),hex32(input.key_hash)), false);
await rejected(signedTransaction(revokedFields,zkSignature({ input,publisherId,proof,digest:transactionDigest(revokedFields),wallet:device })), 'revoked issuer key');
assert.equal(await token.balanceOf(recipient), 2000n);
console.log(JSON.stringify({ result:'PASS', account,publisherId,deviceKey:device.address,recipient,provider:'synthetic RS256 only',proofBytes:256 }));
