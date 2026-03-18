import { expect } from "chai";
import hre from "hardhat";

describe("TokenIDSDIDRegistry", function () {

  async function deployFixture() {
    const [admin, issuer, user1, user2, attacker] =
      await hre.viem.getWalletClients();

    const registry = await hre.viem.deployContract(
      "TokenIDSDIDRegistry",
      [admin.account.address, issuer.account.address]
    );

    const publicClient = await hre.viem.getPublicClient();
    const chainId = BigInt(await publicClient.getChainId());

    const user1DIDUri = `did:tokenids:polygon:${chainId}:${user1.account.address}`;
    const user2DIDUri = `did:tokenids:polygon:${chainId}:${user2.account.address}`;
    const user1DocHash = `0x${"a".repeat(64)}`;
    const user2DocHash = `0x${"b".repeat(64)}`;
    const zeroHash    = `0x${"0".repeat(64)}`;
    const zkProof     = `0x${"c".repeat(64)}`;

    return {
      registry, admin, issuer, user1, user2, attacker,
      publicClient, chainId,
      user1DIDUri, user2DIDUri,
      user1DocHash, user2DocHash,
      zeroHash, zkProof
    };
  }

  // ── 1. Despliegue ──────────────────────────────────────────────────────────

  describe("1. Despliegue y configuracion inicial", function () {

    it("debe tener VERSION = 1.0.0", async function () {
      const { registry } = await deployFixture();
      expect(await registry.read.VERSION()).to.equal("1.0.0");
    });

    it("debe tener estadisticas iniciales en cero", async function () {
      const { registry } = await deployFixture();
      const [totalDIDs, totalCreds] = await registry.read.getStats();
      expect(totalDIDs).to.equal(0n);
      expect(totalCreds).to.equal(0n);
    });

    it("admin tiene DEFAULT_ADMIN_ROLE", async function () {
      const { registry, admin } = await deployFixture();
      const DEFAULT_ADMIN_ROLE = `0x${"0".repeat(64)}`;
      expect(
        await registry.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address])
      ).to.be.true;
    });

    it("issuer tiene ISSUER_ROLE", async function () {
      const { registry, issuer } = await deployFixture();
      const ISSUER_ROLE = hre.ethers
        ? hre.ethers.id("ISSUER_ROLE")
        : `0x${Buffer.from("ISSUER_ROLE").toString("hex").padStart(64, "0")}`;
      const roleHash = "0x" + Array.from(
        new Uint8Array(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode("ISSUER_ROLE")
          )
        )
      ).map(b => b.toString(16).padStart(2, "0")).join("");
      const roles = await registry.read.ISSUER_ROLE();
      expect(
        await registry.read.hasRole([roles, issuer.account.address])
      ).to.be.true;
    });

  });

  // ── 2. createDID ──────────────────────────────────────────────────────────

  describe("2. createDID — W3C DID Core 1.0 Create", function () {

    it("debe crear un DID y asociar la direccion", async function () {
      const { registry, user1, user1DIDUri, user1DocHash, zeroHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash = await registry.read.getDIDByAddress(
        [user1.account.address]
      );
      expect(didHash).to.not.equal(zeroHash);
    });

    it("debe incrementar totalDIDs a 1", async function () {
      const { registry, user1, user1DIDUri, user1DocHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const [totalDIDs] = await registry.read.getStats();
      expect(totalDIDs).to.equal(1n);
    });

    it("debe revertir con documentHash cero", async function () {
      const { registry, user1, user1DIDUri, zeroHash } = await deployFixture();

      await expect(
        registry.write.createDID(
          [user1DIDUri, zeroHash],
          { account: user1.account }
        )
      ).to.be.rejected;
    });

    it("debe revertir si el usuario ya tiene DID", async function () {
      const { registry, user1, user1DIDUri, user1DocHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      await expect(
        registry.write.createDID(
          [user1DIDUri, user1DocHash],
          { account: user1.account }
        )
      ).to.be.rejected;
    });

  });

  // ── 3. updateDID ──────────────────────────────────────────────────────────

  describe("3. updateDID — W3C DID Core 1.0 Update", function () {

    it("controller puede actualizar el documentHash", async function () {
      const { registry, user1, user1DIDUri, user1DocHash, user2DocHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash = await registry.read.getDIDByAddress(
        [user1.account.address]
      );

      await registry.write.updateDID(
        [didHash, user2DocHash],
        { account: user1.account }
      );

      const record = await registry.read.resolveDID([didHash]);
      expect(record.documentHash).to.equal(user2DocHash);
    });

    it("no-controller no puede actualizar", async function () {
      const { registry, user1, user2, user1DIDUri, user1DocHash, user2DocHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash = await registry.read.getDIDByAddress(
        [user1.account.address]
      );

      await expect(
        registry.write.updateDID(
          [didHash, user2DocHash],
          { account: user2.account }
        )
      ).to.be.rejected;
    });

  });

  // ── 4. deactivateDID ──────────────────────────────────────────────────────

  describe("4. deactivateDID — GDPR Art. 17 Derecho al olvido", function () {

    it("debe desactivar el DID — active = false", async function () {
      const { registry, user1, user1DIDUri, user1DocHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash = await registry.read.getDIDByAddress(
        [user1.account.address]
      );

      await registry.write.deactivateDID(
        [didHash],
        { account: user1.account }
      );

      const record = await registry.read.resolveDID([didHash]);
      expect(record.active).to.be.false;
    });

    it("debe liberar la asociacion address => DID", async function () {
      const { registry, user1, user1DIDUri, user1DocHash, zeroHash } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash = await registry.read.getDIDByAddress(
        [user1.account.address]
      );

      await registry.write.deactivateDID(
        [didHash],
        { account: user1.account }
      );

      const result = await registry.read.getDIDByAddress(
        [user1.account.address]
      );
      expect(result).to.equal(zeroHash);
    });

  });

  // ── 5. issueCredential ────────────────────────────────────────────────────

  describe("5. issueCredential — W3C VC Data Model 2.0", function () {

    it("issuer puede emitir KYCCredential", async function () {
      const { registry, issuer, user1, user1DIDUri, user1DocHash, zkProof } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash  = await registry.read.getDIDByAddress([user1.account.address]);
      const dataHash = `0x${"d".repeat(64)}`;
      const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 86400);

      await registry.write.issueCredential(
        [didHash, "KYCCredential", dataHash, expiresAt, zkProof],
        { account: issuer.account }
      );

      const [, totalCreds] = await registry.read.getStats();
      expect(totalCreds).to.equal(1n);
    });

    it("no-issuer no puede emitir credencial", async function () {
      const { registry, user1, user2, user1DIDUri, user1DocHash, zkProof } =
        await deployFixture();

      await registry.write.createDID(
        [user1DIDUri, user1DocHash],
        { account: user1.account }
      );

      const didHash  = await registry.read.getDIDByAddress([user1.account.address]);
      const dataHash = `0x${"d".repeat(64)}`;

      await expect(
        registry.write.issueCredential(
          [didHash, "KYCCredential", dataHash, 0n, zkProof],
          { account: user2.account }
        )
      ).to.be.rejected;
    });

  });

  // ── 6. Pause / Unpause ────────────────────────────────────────────────────

  describe("6. Pause / Unpause — Control de emergencia", function () {

    it("admin puede pausar el contrato", async function () {
      const { registry, admin, user1, user1DIDUri, user1DocHash } =
        await deployFixture();

      await registry.write.pause({ account: admin.account });

      await expect(
        registry.write.createDID(
          [user1DIDUri, user1DocHash],
          { account: user1.account }
        )
      ).to.be.rejected;
    });

    it("no-pauser no puede pausar", async function () {
      const { registry, attacker } = await deployFixture();

      await expect(
        registry.write.pause({ account: attacker.account })
      ).to.be.rejected;
    });

  });

});