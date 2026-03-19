import { expect } from "chai";
import hre from "hardhat";

/**
 * Tests unitarios — ERC-3643 TokenIDSAsset
 *
 * Cobertura:
 *   - IdentityRegistry: registro y verificacion de identidades
 *   - ComplianceManager: reglas de compliance on-chain
 *   - TokenIDSAsset: tokenizacion y transferencias reguladas
 *
 * Normativa verificada:
 *   - ERC-3643 T-REX — compliance en transferencias
 *   - FATF R.16 — Travel Rule umbral 1.000 USD
 *   - SAGRILAFT — umbral reporte 10.000 USD
 *   - GDPR Art.17 / Ley 1581 — removeIdentity
 *
 * TFM Reference: Fase 2 — Sprint 2.1 — Tests ERC-3643
 */
describe("ERC-3643 TokenIDS Suite", function () {

  this.timeout(120000);

  async function deployFullSuite() {
    const [admin, issuer, investor1, investor2, attacker] =
      await hre.viem.getWalletClients();

    const didRegistry = await hre.viem.deployContract(
      "TokenIDSDIDRegistry",
      [admin.account.address, issuer.account.address]
    );

    const identityRegistry = await hre.viem.deployContract(
      "IdentityRegistry",
      [admin.account.address, didRegistry.address]
    );

    const complianceManager = await hre.viem.deployContract(
      "ComplianceManager",
      [admin.account.address, identityRegistry.address, 100n, 0n]
    );

    const asset = await hre.viem.deployContract(
      "TokenIDSAsset",
      [
        "Casa Bogota 001",
        "TKIDS-CB001",
        admin.account.address,
        complianceManager.address,
      ]
    );

    const pub     = await hre.viem.getPublicClient();
    const chainId = BigInt(await pub.getChainId());

    const inv1DIDUri = `did:tokenids:polygon:${chainId}:${investor1.account.address}`;
    const inv2DIDUri = `did:tokenids:polygon:${chainId}:${investor2.account.address}`;
    const docHash  = `0x${"a".repeat(64)}` as `0x${string}`;
    const zkProof  = `0x${"b".repeat(64)}` as `0x${string}`;
    const dataHash = `0x${"c".repeat(64)}` as `0x${string}`;
    const assetId  = `0x${"d".repeat(64)}` as `0x${string}`;
    const docAsset = `0x${"e".repeat(64)}` as `0x${string}`;

    async function registerInvestor(
      wallet: typeof investor1,
      didUri: string
    ) {
      await didRegistry.write.createDID(
        [didUri, docHash],
        { account: wallet.account }
      );
      const didHash = await didRegistry.read.getDIDByAddress(
        [wallet.account.address]
      );
      const exp = BigInt(Math.floor(Date.now() / 1000) + 365 * 86400);
      await didRegistry.write.issueCredential(
        [didHash, "KYCCredential", dataHash, exp, zkProof],
        { account: issuer.account }
      );
      const credentials = await didRegistry.read.getCredentialsByDID(
        [didHash]
      );
      const credId = credentials[credentials.length - 1];
      await identityRegistry.write.registerIdentity(
        [wallet.account.address, credId],
        { account: admin.account }
      );
      return { didHash, credId };
    }

    return {
      didRegistry, identityRegistry, complianceManager, asset,
      admin, issuer, investor1, investor2, attacker,
      inv1DIDUri, inv2DIDUri,
      docHash, zkProof, dataHash, assetId, docAsset,
      registerInvestor
    };
  }

  // ══════════════════════════════════════════════════════════
  // SUITE 1 — IdentityRegistry
  // ══════════════════════════════════════════════════════════

  describe("1. IdentityRegistry", function () {

    it("registra una identidad KYC verificada", async function () {
      const { identityRegistry, investor1, inv1DIDUri,
              registerInvestor } = await deployFullSuite();

      await registerInvestor(investor1, inv1DIDUri);

      expect(
        await identityRegistry.read.isVerified(
          [investor1.account.address]
        )
      ).to.be.true;
    });

    it("totalVerified incrementa a 1", async function () {
      const { identityRegistry, investor1, inv1DIDUri,
              registerInvestor } = await deployFullSuite();

      await registerInvestor(investor1, inv1DIDUri);

      expect(
        await identityRegistry.read.totalVerified()
      ).to.equal(1n);
    });

    it("wallet sin KYC devuelve isVerified = false",
      async function () {
      const { identityRegistry, attacker } = await deployFullSuite();

      expect(
        await identityRegistry.read.isVerified(
          [attacker.account.address]
        )
      ).to.be.false;
    });

    it("revierte si wallet ya esta verificada", async function () {
      const { identityRegistry, investor1, inv1DIDUri,
              registerInvestor, admin } = await deployFullSuite();

      const { credId } = await registerInvestor(investor1, inv1DIDUri);

      await expect(
        identityRegistry.write.registerIdentity(
          [investor1.account.address, credId],
          { account: admin.account }
        )
      ).to.be.rejected;
    });

    it("removeIdentity implementa derecho al olvido — GDPR Art.17",
      async function () {
      const { identityRegistry, investor1, inv1DIDUri,
              registerInvestor, admin } = await deployFullSuite();

      await registerInvestor(investor1, inv1DIDUri);

      expect(
        await identityRegistry.read.isVerified(
          [investor1.account.address]
        )
      ).to.be.true;

      await identityRegistry.write.removeIdentity(
        [investor1.account.address],
        { account: admin.account }
      );

      expect(
        await identityRegistry.read.isVerified(
          [investor1.account.address]
        )
      ).to.be.false;

      expect(
        await identityRegistry.read.totalVerified()
      ).to.equal(0n);
    });

    it("revierte si wallet sin DID intenta registrarse",
      async function () {
      const { identityRegistry, attacker, dataHash, admin } =
        await deployFullSuite();

      await expect(
        identityRegistry.write.registerIdentity(
          [attacker.account.address, dataHash],
          { account: admin.account }
        )
      ).to.be.rejected;
    });

  });

  // ══════════════════════════════════════════════════════════
  // SUITE 2 — ComplianceManager
  // ══════════════════════════════════════════════════════════

  describe("2. ComplianceManager", function () {

    it("valores iniciales correctos — FATF R.16 y SAGRILAFT",
      async function () {
      const { complianceManager } = await deployFullSuite();

      expect(
        await complianceManager.read.travelRuleThresholdUSD()
      ).to.equal(1_000n);
      expect(
        await complianceManager.read.sagrilaftThresholdUSD()
      ).to.equal(10_000n);
      expect(
        await complianceManager.read.tokenPriceUSD()
      ).to.equal(100n);
    });

    it("blacklist bloquea una direccion", async function () {
      const { complianceManager, attacker, admin } =
        await deployFullSuite();

      await complianceManager.write.blacklist(
        [attacker.account.address],
        { account: admin.account }
      );

      expect(
        await complianceManager.read.isBlacklisted(
          [attacker.account.address]
        )
      ).to.be.true;
    });

    it("whitelist desbloquea una direccion", async function () {
      const { complianceManager, attacker, admin } =
        await deployFullSuite();

      await complianceManager.write.blacklist(
        [attacker.account.address],
        { account: admin.account }
      );
      await complianceManager.write.whitelist(
        [attacker.account.address],
        { account: admin.account }
      );

      expect(
        await complianceManager.read.isBlacklisted(
          [attacker.account.address]
        )
      ).to.be.false;
    });

    it("no-compliance-role no puede blacklistear", async function () {
      const { complianceManager, attacker } = await deployFullSuite();

      await expect(
        complianceManager.write.blacklist(
          [attacker.account.address],
          { account: attacker.account }
        )
      ).to.be.rejected;
    });

    it("actualiza umbral Travel Rule", async function () {
      const { complianceManager, admin } = await deployFullSuite();

      await complianceManager.write.setTravelRuleThreshold(
        [2_000n],
        { account: admin.account }
      );

      expect(
        await complianceManager.read.travelRuleThresholdUSD()
      ).to.equal(2_000n);
    });

  });

  // ══════════════════════════════════════════════════════════
  // SUITE 3 — TokenIDSAsset — Tokenizacion
  // ══════════════════════════════════════════════════════════

  describe("3. TokenIDSAsset — Tokenizacion ERC-3643", function () {

    it("tokeniza un activo correctamente", async function () {
      const { asset, assetId, docAsset, admin } =
        await deployFullSuite();

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      const metadata = await asset.read.getAssetMetadata();
      expect(metadata.assetType).to.equal("INMUEBLE");
      expect(metadata.valueUSD).to.equal(50_000n);
      expect(metadata.active).to.be.true;
      expect(await asset.read.totalSupply()).to.equal(1_000n);
    });

    it("precio por token = valueUSD / totalSupply", async function () {
      const { asset, assetId, docAsset, admin } =
        await deployFullSuite();

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      expect(await asset.read.pricePerToken()).to.equal(50n);
    });

    it("solo puede tokenizarse una vez", async function () {
      const { asset, assetId, docAsset, admin } =
        await deployFullSuite();

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      await expect(
        asset.write.tokenizeAsset(
          [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
          { account: admin.account }
        )
      ).to.be.rejected;
    });

    it("transfer() estandar ERC-20 esta deshabilitado",
      async function () {
      const { asset, investor1 } = await deployFullSuite();

      await expect(
        asset.write.transfer(
          [investor1.account.address, 100n],
          { account: investor1.account }
        )
      ).to.be.rejected;
    });

  });

  // ══════════════════════════════════════════════════════════
  // SUITE 4 — Transferencias con Compliance ERC-3643
  // ══════════════════════════════════════════════════════════

  describe("4. Transferencias con Compliance — ERC-3643",
    function () {

    async function tokenizedSuite() {
      const suite = await deployFullSuite();
      const { asset, assetId, docAsset, admin,
              investor1, investor2,
              inv1DIDUri, inv2DIDUri,
              registerInvestor } = suite;

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      const adminDIDUri =
        `did:tokenids:polygon:31337:${admin.account.address}`;
      await registerInvestor(admin, adminDIDUri);
      await registerInvestor(investor1, inv1DIDUri);
      await registerInvestor(investor2, inv2DIDUri);

      return suite;
    }

    it("transferencia exitosa entre inversores KYC verificados",
      async function () {
      const { asset, admin, investor1 } = await tokenizedSuite();

      await asset.write.transferWithCompliance(
        [investor1.account.address, 100n],
        { account: admin.account }
      );

      expect(
        await asset.read.balanceOf([investor1.account.address])
      ).to.equal(100n);
      expect(
        await asset.read.balanceOf([admin.account.address])
      ).to.equal(900n);
    });

    it("revierte si emisor no tiene KYC", async function () {
      const { asset, attacker, investor1 } = await deployFullSuite();

      await expect(
        asset.write.transferWithCompliance(
          [investor1.account.address, 100n],
          { account: attacker.account }
        )
      ).to.be.rejected;
    });

    it("revierte si receptor no tiene KYC", async function () {
      const { asset, assetId, docAsset, admin, attacker,
              registerInvestor } = await deployFullSuite();

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      const adminDIDUri =
        `did:tokenids:polygon:31337:${admin.account.address}`;
      await registerInvestor(admin, adminDIDUri);

      await expect(
        asset.write.transferWithCompliance(
          [attacker.account.address, 100n],
          { account: admin.account }
        )
      ).to.be.rejected;
    });

    it("canTransfer devuelve false sin KYC", async function () {
      const { asset, admin, attacker } = await deployFullSuite();

      expect(
        await asset.read.canTransfer(
          [admin.account.address, attacker.account.address, 100n]
        )
      ).to.be.false;
    });

    it("canTransfer devuelve true con KYC en ambos lados",
      async function () {
      const { asset, admin, investor1 } = await tokenizedSuite();

      expect(
        await asset.read.canTransfer(
          [admin.account.address, investor1.account.address, 100n]
        )
      ).to.be.true;
    });

    it("blacklist bloquea transferencia — screening OFAC/UIAF",
      async function () {
      const { asset, complianceManager, admin, investor1 } =
        await tokenizedSuite();

      await complianceManager.write.blacklist(
        [investor1.account.address],
        { account: admin.account }
      );

      await expect(
        asset.write.transferWithCompliance(
          [investor1.account.address, 100n],
          { account: admin.account }
        )
      ).to.be.rejected;
    });

    it("getStats registra checks tras transferencia exitosa",
      async function () {
      const { complianceManager, asset, admin, investor1,
              inv1DIDUri, registerInvestor,
              assetId, docAsset } = await deployFullSuite();

      await asset.write.tokenizeAsset(
        [assetId, "INMUEBLE", 50_000n, 1_000n, docAsset],
        { account: admin.account }
      );

      const adminDIDUri =
        `did:tokenids:polygon:31337:${admin.account.address}`;
      await registerInvestor(admin, adminDIDUri);
      await registerInvestor(investor1, inv1DIDUri);

      await asset.write.transferWithCompliance(
        [investor1.account.address, 10n],
        { account: admin.account }
      );

      const [checks, blocked] =
        await complianceManager.read.getStats();

      expect(checks > 0n).to.be.true;
      expect(blocked).to.equal(0n);
    });

  });

});