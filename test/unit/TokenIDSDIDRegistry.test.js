const { expect } = await import("chai");
import hre from "hardhat";
import { describe, it } from "node:test";

describe("TokenIDSDIDRegistry", function () {

  async function deploy() {
    const [admin, issuer, user1, user2, attacker] =
      await hre.viem.getWalletClients();
    const registry = await hre.viem.deployContract(
      "TokenIDSDIDRegistry",
      [admin.account.address, issuer.account.address]
    );
    const pub = await hre.viem.getPublicClient();
    const chainId = BigInt(await pub.getChainId());
    const uri1  = `did:tokenids:polygon:${chainId}:${user1.account.address}`;
    const doc1  = `0x${"a".repeat(64)}`;
    const doc2  = `0x${"b".repeat(64)}`;
    const zero  = `0x${"0".repeat(64)}`;
    const proof = `0x${"c".repeat(64)}`;
    return { registry, admin, issuer, user1, user2, attacker,
             uri1, doc1, doc2, zero, proof };
  }

  it("VERSION = 1.0.0", async function () {
    const { registry } = await deploy();
    expect(await registry.read.VERSION()).to.equal("1.0.0");
  });

  it("estadisticas iniciales en cero", async function () {
    const { registry } = await deploy();
    const [d, c] = await registry.read.getStats();
    expect(d).to.equal(0n);
    expect(c).to.equal(0n);
  });

  it("crea DID y asocia direccion", async function () {
    const { registry, user1, uri1, doc1, zero } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    expect(h).to.not.equal(zero);
  });

  it("incrementa totalDIDs a 1", async function () {
    const { registry, user1, uri1, doc1 } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const [d] = await registry.read.getStats();
    expect(d).to.equal(1n);
  });

  it("revierte con documentHash cero", async function () {
    const { registry, user1, uri1, zero } = await deploy();
    await expect(
      registry.write.createDID([uri1, zero], { account: user1.account })
    ).to.be.rejected;
  });

  it("revierte si usuario ya tiene DID", async function () {
    const { registry, user1, uri1, doc1 } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    await expect(
      registry.write.createDID([uri1, doc1], { account: user1.account })
    ).to.be.rejected;
  });

  it("controller actualiza documentHash", async function () {
    const { registry, user1, uri1, doc1, doc2 } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    await registry.write.updateDID([h, doc2], { account: user1.account });
    const rec = await registry.read.resolveDID([h]);
    expect(rec.documentHash).to.equal(doc2);
  });

  it("no-controller no puede actualizar", async function () {
    const { registry, user1, user2, uri1, doc1, doc2 } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    await expect(
      registry.write.updateDID([h, doc2], { account: user2.account })
    ).to.be.rejected;
  });

  it("desactiva DID — active = false", async function () {
    const { registry, user1, uri1, doc1 } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    await registry.write.deactivateDID([h], { account: user1.account });
    const rec = await registry.read.resolveDID([h]);
    expect(rec.active).to.be.false;
  });

  it("libera asociacion address => DID tras deactivate", async function () {
    const { registry, user1, uri1, doc1, zero } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    await registry.write.deactivateDID([h], { account: user1.account });
    const r = await registry.read.getDIDByAddress([user1.account.address]);
    expect(r).to.equal(zero);
  });

  it("issuer emite KYCCredential", async function () {
    const { registry, issuer, user1, uri1, doc1, proof } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    const data = `0x${"d".repeat(64)}`;
    const exp = BigInt(Math.floor(Date.now()/1000) + 365*86400);
    await registry.write.issueCredential(
      [h, "KYCCredential", data, exp, proof],
      { account: issuer.account }
    );
    const [, c] = await registry.read.getStats();
    expect(c).to.equal(1n);
  });

  it("no-issuer no puede emitir", async function () {
    const { registry, user1, user2, uri1, doc1, proof } = await deploy();
    await registry.write.createDID([uri1, doc1], { account: user1.account });
    const h = await registry.read.getDIDByAddress([user1.account.address]);
    const data = `0x${"d".repeat(64)}`;
    await expect(
      registry.write.issueCredential(
        [h, "KYCCredential", data, 0n, proof],
        { account: user2.account }
      )
    ).to.be.rejected;
  });

  it("admin pausa el contrato", async function () {
    const { registry, admin, user1, uri1, doc1 } = await deploy();
    await registry.write.pause({ account: admin.account });
    await expect(
      registry.write.createDID([uri1, doc1], { account: user1.account })
    ).to.be.rejected;
  });

  it("no-pauser no puede pausar", async function () {
    const { registry, attacker } = await deploy();
    await expect(
      registry.write.pause({ account: attacker.account })
    ).to.be.rejected;
  });

});
