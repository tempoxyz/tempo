import { ethers } from "hardhat";
import chai from "chai";

import { TestEd25519 } from '../typechain';
import { verify } from "crypto";

const { expect } = chai;

describe('Ed25519', () => {
    let ed25519: TestEd25519

    before('deploy Ed25519', async () => {
        const ed25519Factory = await ethers.getContractFactory('TestEd25519')
        ed25519 = (await ed25519Factory.deploy()) as TestEd25519
    })

    for (const { description, pub, msg, sig, valid } of require('./ed25519-tests.json')) {
        it(description, async () => {
            const [r, s] = [sig.substring(0, 64), sig.substring(64)];
            expect(valid).to.eq(await ed25519.verify(`0x${pub}`, `0x${r}`, `0x${s}`, `0x${msg}`))
       });
    }
})