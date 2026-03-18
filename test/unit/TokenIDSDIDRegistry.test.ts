import { expect } from "chai";
import hre from "hardhat";

describe("TokenIDSDIDRegistry", function () {

  this.timeout(60000);

  async function deploy() {
    const [admin, issuer, user1, user2, attacker] =
      await hre.viem.getWalletClients();

    const registry = await hre.viem.deployContract(
      "TokenIDSDIDRegistry",
      [admin.account.address, issuer.account.address]
    );

    const pub     = await hre.viem.getPublicClient();
    const chainId = BigInt(await pub.getChainId());
    const uri1    = `did:tokenids:polygon:${chainId}:${user1.account.address}`;
    const uri2    = `did:tokenids:polygon:${chainId}:${user2.account.address}`;
    const doc1    = `0x${"a".repeat(64)}` as `0x${string}`;
    const doc2    = `0x${"b".repeat(64)}` as `0x${string}`;
    const zero    = `0x${"0".repeat(64)}` as `0x${string}`;
    const proof   = `0x${"c".repeat(64)}` as `0x${string}`;

    return {
      registry, admin, issuer, user1, user2, attacker,
      uri1, uri2, doc1, doc2, zero, proof
    };
  }

  // ── 1. Despliegue ──────────────────────────────────────────

  describe("1. Despliegue y configuracion inicial", function () {

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

    it("admin tiene DEFAULT_ADMIN_ROLE", async function () {
      const { registry, admin } = await deploy();
      const role = `0x${"0".repeat(64)}` as `0x${string}`;
      expect(
        await registry.read.hasRole([role, admin.account.address])
      ).to.be.true;
    });

    it("issuer tiene ISSUER_ROLE", async function () {
      const { registry, issuer } = await deploy();
      const role = await registry.read.ISSUER_ROLE();
      expect(
        await registry.read.hasRole([role, issuer.account.address])
      ).to.be.true;
    });

  });

  // ── 2. createDID ───────────────────────────────────────────

  describe("2. createDID — W3C DID Core 1.0 Create", function () {

    it("crea DID y asocia la direccion", async function () {
      const { registry, user1, uri1, doc1, zero } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      expect(h).to.not.equal(zero);
    });

    it("incrementa totalDIDs a 1", async function () {
      const { registry, user1, uri1, doc1 } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const [d] = await registry.read.getStats();
      expect(d).to.equal(1n);
    });

    it("revierte con documentHash cero", async function () {
      const { registry, user1, uri1, zero } = await deploy();
      await expect(
        registry.write.createDID([uri1, zero],
          { account: user1.account })
      ).to.be.rejected;
    });

    it("revierte si usuario ya tiene DID", async function () {
      const { registry, user1, uri1, doc1 } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      await expect(
        registry.write.createDID([uri1, doc1],
          { account: user1.account })
      ).to.be.rejected;
    });

  });

  // ── 3. updateDID ───────────────────────────────────────────

  describe("3. updateDID — W3C DID Core 1.0 Update", function () {

    it("controller actualiza el documentHash", async function () {
      const { registry, user1, uri1, doc1, doc2 } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      await registry.write.updateDID([h, doc2],
        { account: user1.account });
      const rec = await registry.read.resolveDID([h]);
      expect(rec.documentHash).to.equal(doc2);
    });

    it("no-controller no puede actualizar", async function () {
      const { registry, user1, user2, uri1, doc1, doc2 } =
        await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      await expect(
        registry.write.updateDID([h, doc2],
          { account: user2.account })
      ).to.be.rejected;
    });

  });

  // ── 4. deactivateDID ───────────────────────────────────────

  describe("4. deactivateDID — GDPR Art.17 Derecho al olvido",
    function () {

    it("desactiva DID — active = false", async function () {
      const { registry, user1, uri1, doc1 } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      await registry.write.deactivateDID([h],
        { account: user1.account });
      const rec = await registry.read.resolveDID([h]);
      expect(rec.active).to.be.false;
    });

    it("libera la asociacion address => DID", async function () {
      const { registry, user1, uri1, doc1, zero } = await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      await registry.write.deactivateDID([h],
        { account: user1.account });
      const r = await registry.read.getDIDByAddress(
        [user1.account.address]);
      expect(r).to.equal(zero);
    });

  });

  // ── 5. issueCredential ─────────────────────────────────────

  describe("5. issueCredential — W3C VC Data Model 2.0",
    function () {

    it("issuer emite KYCCredential correctamente", async function () {
      const { registry, issuer, user1, uri1, doc1, proof } =
        await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      const data = `0x${"d".repeat(64)}` as `0x${string}`;
      const exp  = BigInt(
        Math.floor(Date.now() / 1000) + 365 * 86400);
      await registry.write.issueCredential(
        [h, "KYCCredential", data, exp, proof],
        { account: issuer.account }
      );
      const [, c] = await registry.read.getStats();
      expect(c).to.equal(1n);
    });

    it("no-issuer no puede emitir credencial", async function () {
      const { registry, user1, user2, uri1, doc1, proof } =
        await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      const data = `0x${"d".repeat(64)}` as `0x${string}`;
      await expect(
        registry.write.issueCredential(
          [h, "KYCCredential", data, 0n, proof],
          { account: user2.account }
        )
      ).to.be.rejected;
    });

    it("DID inactivo no puede recibir credencial", async function () {
      const { registry, issuer, user1, uri1, doc1, proof } =
        await deploy();
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const h = await registry.read.getDIDByAddress(
        [user1.account.address]);
      await registry.write.deactivateDID([h],
        { account: user1.account });
      const data = `0x${"d".repeat(64)}` as `0x${string}`;
      await expect(
        registry.write.issueCredential(
          [h, "KYCCredential", data, 0n, proof],
          { account: issuer.account }
        )
      ).to.be.rejected;
    });

  });

  // ── 6. verifyCredential ────────────────────────────────────

  describe("6. verifyCredential — Verificacion on-chain",
    function () {

    it("credencial inexistente devuelve false", async function () {
      const { registry } = await deploy();
      const fakeId = `0x${"f".repeat(64)}` as `0x${string}`;
      const result = await registry.read.verifyCredential([fakeId]);
      expect(result).to.be.false;
    });

  });

  // ── 7. Pause / Unpause ─────────────────────────────────────

  describe("7. Pause / Unpause — Control de emergencia",
    function () {

    it("admin puede pausar el contrato", async function () {
      const { registry, admin, user1, uri1, doc1 } = await deploy();
      await registry.write.pause({ account: admin.account });
      await expect(
        registry.write.createDID([uri1, doc1],
          { account: user1.account })
      ).to.be.rejected;
    });

    it("no-pauser no puede pausar", async function () {
      const { registry, attacker } = await deploy();
      await expect(
        registry.write.pause({ account: attacker.account })
      ).to.be.rejected;
    });

    it("admin puede reanudar tras pausa", async function () {
      const { registry, admin, user1, uri1, doc1 } = await deploy();
      await registry.write.pause({ account: admin.account });
      await registry.write.unpause({ account: admin.account });
      await registry.write.createDID([uri1, doc1],
        { account: user1.account });
      const [d] = await registry.read.getStats();
      expect(d).to.equal(1n);
    });

  });

});