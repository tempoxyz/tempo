import * as ethers from '/ethers.js';

const status = document.querySelector('#status');
const config = await (await fetch('/config')).json();
let wallet;
let challenge;
let authorized;
let nonce = 0;
const q = value => BigInt(value) === 0n ? '0x' : ethers.toBeHex(BigInt(value));
const b32 = value => ethers.toBeHex(BigInt(value),32);
const USD = '0x20c0000000000000000000000000000000000000';
const token = new ethers.Interface(['function transfer(address,uint256) returns(bool)']);
const post = async (endpoint,body) => {
  const response = await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  return result;
};
function zk(digest) {
  const input = authorized.input;
  const fields = [q(1),config.publisherId,b32(input.issuer),b32(input.key_hash),b32(input.address_seed),q(input.issued_at),q(input.commit_b),authorized.proof];
  const hash = ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('tempo:zk-signature'),digest,ethers.keccak256(ethers.encodeRlp(fields))]));
  return ethers.concat(['0x06',ethers.encodeRlp([...fields,wallet.signingKey.sign(hash).serialized])]);
}
status.textContent = `Google audience: ${config.clientId}\nPrivate chain: ${config.chainId}\nPublish Google JWKS under ${config.publisherId} before paying.`;
document.querySelector('#begin').onclick = async () => {
  try {
    if (!window.google?.accounts?.id) throw new Error('Google sign-in library has not loaded');
    wallet = ethers.Wallet.createRandom();
    challenge = await post('/challenge',{accessKey:wallet.address});
    window.google.accounts.id.initialize({client_id:config.clientId,nonce:challenge.nonce,callback:async ({credential}) => {
      try {
        status.textContent = 'Provider token received; generating RSA proof…';
        authorized = await post('/prove',{id:challenge.id,token:credential});
        status.textContent = `OIDC account: ${authorized.account}\nDevice key: ${wallet.address}\nExpiry: ${authorized.input.commit_b}\nFund this account with test pathUSD, then install and pay.`;
        document.querySelector('#pay').disabled = false;
      } catch(error) { status.textContent = error.message; }
    }});
    window.google.accounts.id.renderButton(document.querySelector('#google'),{theme:'outline',size:'large'});
    status.textContent = `Device key: ${wallet.address}\nUse Google sign-in within 540 seconds.`;
  } catch(error) { status.textContent = error.message; }
};
async function pay(install) {
  const provider = new ethers.JsonRpcProvider(`${window.location.origin}/rpc`,undefined,{cacheTimeout:-1});
  if ((await provider.getNetwork()).chainId !== 1337n) throw new Error('Refusing any chain other than private chain 1337');
  const recipient = document.querySelector('#recipient').value;
  const amount = BigInt(document.querySelector('#amount').value);
  if (!ethers.isAddress(recipient) || amount <= 0n) throw new Error('Invalid recipient or amount');
  nonce = Number(await provider.send('eth_getTransactionCount',[authorized.account,'pending']));
  const fields = [q(1337),'0x',q(1000000000),q(3000000),[[USD,'0x',token.encodeFunctionData('transfer',[recipient,amount])]],[],'0x',q(nonce),install ? q(authorized.input.commit_b) : '0x','0x',USD,'0x',[]];
  if (install) {
    const auth = [q(1337),'0x',wallet.address,q(authorized.input.commit_b)];
    fields.push([auth,zk(ethers.keccak256(ethers.encodeRlp(auth)))]);
  }
  const digest = ethers.keccak256(ethers.concat(['0x76',ethers.encodeRlp(fields)]));
  const signature = install ? zk(digest) : ethers.concat(['0x04',authorized.account,wallet.signingKey.sign(ethers.keccak256(ethers.concat(['0x04',digest,authorized.account]))).serialized]);
  const raw = ethers.concat(['0x76',ethers.encodeRlp([...fields,signature])]);
  const hash = await provider.send('eth_sendRawTransaction',[raw]);
  status.textContent = `Submitted ${hash}; waiting for receipt…`;
  const receipt = await provider.waitForTransaction(hash,1,120000);
  if (receipt.status !== 1) throw new Error('Transaction reverted');
  status.textContent = `Mined ${hash} in block ${receipt.blockNumber}; ${install ? 'proof authorized the device key' : 'device-key payment required no new proof'}.`;
  document.querySelector('#pay').disabled = true;
  document.querySelector('#again').disabled = false;
}
for (const [id,install] of [['pay',true],['again',false]]) document.querySelector(`#${id}`).onclick = async () => {
  document.querySelector(`#${id}`).disabled = true;
  try { await pay(install); } catch(error) { status.textContent = error.message; document.querySelector(`#${id}`).disabled = false; }
};
