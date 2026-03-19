import { expect } from "chai";
import hre from "hardhat";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/**
 * Tests ZKP — AgeVerifier y KYCVerifier
 * TFM Reference: Fase 2 — Sprint 2.4 — Tests ZKP
 */
describe("ZKP Verifiers Suite", function () {

  this.timeout(120000);

  // ── AgeVerifier ────────────────────────────────────────────

  describe("1. AgeVerifier — Prueba de mayoría de edad", function () {

    it("despliega AgeVerifier correctamente", async function () {
      const verifier = await hre.viem.deployContract("AgeVerifier");
      expect(verifier.address).to.match(/^0x[0-9a-fA-F]{40}$/);
    });

    it("verifica prueba ZKP válida — adulto de 35 años",
      async function () {
      const verifier = await hre.viem.deployContract("AgeVerifier");

      // Generar witness e input para adulto de 35 años
      const input = {
        birthYear: 1990,
        birthMonth: 3,
        birthDay: 15,
        currentYear: 2026,
        currentMonth: 3,
        currentDay: 19,
        minAge: 18
      };

      // Escribir input.json
      fs.writeFileSync(
        "circuits/age_verification/input.json",
        JSON.stringify(input)
      );

      // Generar witness
      execSync(
        "node circuits/age_verification/age_verification_js/generate_witness.js " +
        "circuits/age_verification/age_verification_js/age_verification.wasm " +
        "circuits/age_verification/input.json " +
        "circuits/age_verification/witness.wtns",
        { stdio: "pipe" }
      );

      // Generar prueba Groth16
      execSync(
        "snarkjs groth16 prove " +
        "circuits/age_verification/age_verification_final.zkey " +
        "circuits/age_verification/witness.wtns " +
        "circuits/age_verification/proof.json " +
        "circuits/age_verification/public.json",
        { stdio: "pipe" }
      );

      // Leer prueba y señales públicas
      const proof  = JSON.parse(
        fs.readFileSync("circuits/age_verification/proof.json", "utf8")
      );
      const pubSignals = JSON.parse(
        fs.readFileSync("circuits/age_verification/public.json", "utf8")
      );

      // isAdult debe ser 1
      expect(pubSignals[0]).to.equal("1");

      // Verificar on-chain
      const pA: [`0x${string}`, `0x${string}`] = [
        `0x${BigInt(proof.pi_a[0]).toString(16).padStart(64, "0")}`,
        `0x${BigInt(proof.pi_a[1]).toString(16).padStart(64, "0")}`
      ];
      const pB: [[`0x${string}`, `0x${string}`],
                 [`0x${string}`, `0x${string}`]] = [
        [
          `0x${BigInt(proof.pi_b[0][1]).toString(16).padStart(64, "0")}`,
          `0x${BigInt(proof.pi_b[0][0]).toString(16).padStart(64, "0")}`
        ],
        [
          `0x${BigInt(proof.pi_b[1][1]).toString(16).padStart(64, "0")}`,
          `0x${BigInt(proof.pi_b[1][0]).toString(16).padStart(64, "0")}`
        ]
      ];
      const pC: [`0x${string}`, `0x${string}`] = [
        `0x${BigInt(proof.pi_c[0]).toString(16).padStart(64, "0")}`,
        `0x${BigInt(proof.pi_c[1]).toString(16).padStart(64, "0")}`
      ];
      const publicInputs = pubSignals.map(
        (s: string) => BigInt(s)
      ) as [bigint, bigint, bigint, bigint, bigint];

      const result = await verifier.read.verifyProof(
        [pA, pB, pC, publicInputs]
      );
      expect(result).to.be.true;
    });

    it("rechaza prueba con menor de edad", async function () {
      const verifier = await hre.viem.deployContract("AgeVerifier");

      const input = {
        birthYear: 2015,
        birthMonth: 1,
        birthDay: 1,
        currentYear: 2026,
        currentMonth: 3,
        currentDay: 19,
        minAge: 18
      };

      fs.writeFileSync(
        "circuits/age_verification/input_minor.json",
        JSON.stringify(input)
      );

      execSync(
        "node circuits/age_verification/age_verification_js/generate_witness.js " +
        "circuits/age_verification/age_verification_js/age_verification.wasm " +
        "circuits/age_verification/input_minor.json " +
        "circuits/age_verification/witness_minor.wtns",
        { stdio: "pipe" }
      );

      execSync(
        "snarkjs groth16 prove " +
        "circuits/age_verification/age_verification_final.zkey " +
        "circuits/age_verification/witness_minor.wtns " +
        "circuits/age_verification/proof_minor.json " +
        "circuits/age_verification/public_minor.json",
        { stdio: "pipe" }
      );

      const pubSignals = JSON.parse(
        fs.readFileSync(
          "circuits/age_verification/public_minor.json", "utf8"
        )
      );

      // isAdult debe ser 0 para menor de edad
      expect(pubSignals[0]).to.equal("0");
    });

  });

  // ── KYCVerifier ────────────────────────────────────────────

  describe("2. KYCVerifier — Prueba de KYC aprobado", function () {

    it("despliega KYCVerifier correctamente", async function () {
      const verifier = await hre.viem.deployContract("KYCVerifier");
      expect(verifier.address).to.match(/^0x[0-9a-fA-F]{40}$/);
    });

  });

});