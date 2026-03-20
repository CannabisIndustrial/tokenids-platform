import hre from "hardhat";
import { writeFileSync, mkdirSync } from "fs";

async function main() {
  const network = hre.network.name;
  console.log(`\nDeploying TokenIDS to ${network}...`);
  console.log("=".repeat(50));

  const [deployer] = await hre.viem.getWalletClients();
  const pub = await hre.viem.getPublicClient();

  console.log("Deployer:", deployer.account.address);

  const balance = await pub.getBalance({
    address: deployer.account.address
  });
  console.log("Balance:", (Number(balance) / 1e18).toFixed(4), "POL");

  if (balance === 0n) {
    throw new Error("Balance cero — obtén POL del faucet primero");
  }

  console.log("\n[1/6] Deploying TokenIDSDIDRegistry...");
  const didRegistry = await hre.viem.deployContract(
    "TokenIDSDIDRegistry",
    [deployer.account.address, deployer.account.address]
  );
  console.log("✅ TokenIDSDIDRegistry:", didRegistry.address);

  console.log("\n[2/6] Deploying IdentityRegistry...");
  const identityRegistry = await hre.viem.deployContract(
    "IdentityRegistry",
    [deployer.account.address, didRegistry.address]
  );
  console.log("✅ IdentityRegistry:", identityRegistry.address);

  console.log("\n[3/6] Deploying ComplianceManager...");
  const complianceManager = await hre.viem.deployContract(
    "ComplianceManager",
    [deployer.account.address, identityRegistry.address, 100n, 0n]
  );
  console.log("✅ ComplianceManager:", complianceManager.address);

  console.log("\n[4/6] Deploying TokenIDSAsset...");
  const asset = await hre.viem.deployContract(
    "TokenIDSAsset",
    [
      "TokenIDS Casa Bogota 001",
      "TKIDS-CB001",
      deployer.account.address,
      complianceManager.address,
    ]
  );
  console.log("✅ TokenIDSAsset:", asset.address);

  console.log("\n[5/6] Deploying AgeVerifier (ZKP)...");
  const ageVerifier = await hre.viem.deployContract("AgeVerifier");
  console.log("✅ AgeVerifier:", ageVerifier.address);

  console.log("\n[6/6] Deploying KYCVerifier (ZKP)...");
  const kycVerifier = await hre.viem.deployContract("KYCVerifier");
  console.log("✅ KYCVerifier:", kycVerifier.address);

  const deployedAddresses = {
    network,
    chainId:             80002,
    deployedAt:          new Date().toISOString(),
    deployer:            deployer.account.address,
    TokenIDSDIDRegistry: didRegistry.address,
    IdentityRegistry:    identityRegistry.address,
    ComplianceManager:   complianceManager.address,
    TokenIDSAsset:       asset.address,
    AgeVerifier:         ageVerifier.address,
    KYCVerifier:         kycVerifier.address,
  };

  mkdirSync("deployments", { recursive: true });
  writeFileSync(
    "deployments/amoy.json",
    JSON.stringify(deployedAddresses, null, 2)
  );

  console.log("\n" + "=".repeat(50));
  console.log("✅ Deploy completo — Polygon Amoy");
  console.log("📄 Direcciones: deployments/amoy.json");
  console.log(`🔍 https://amoy.polygonscan.com/address/${didRegistry.address}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});