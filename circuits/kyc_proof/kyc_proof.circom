pragma circom 2.2.3;

/*
 * KYCProof Circuit — TokenIDS ZKP
 * =================================
 * Prueba que un usuario tiene KYC aprobado y es mayor de edad
 * sin revelar datos personales ni el resultado del KYC.
 *
 * Inputs privados:
 *   - kycScore:      confidence score del KYC (0-100, escalado x100)
 *   - birthYear:     año de nacimiento
 *   - documentHash:  hash del documento verificado
 *
 * Inputs públicos:
 *   - minKycScore:   umbral mínimo aprobado (90 = 0.90 confidence)
 *   - currentYear:   año actual
 *   - minAge:        edad mínima (18)
 *   - commitment:    hash público que vincula al usuario sin revelar datos
 *
 * Outputs públicos:
 *   - kycValid:  1 si KYC aprobado y mayor de edad
 *
 * Propiedad ZKP:
 *   El verificador confirma que:
 *     1. El usuario tiene confidence score >= minKycScore
 *     2. El usuario tiene >= minAge años
 *   Sin conocer: kycScore exacto, birthYear, documentHash
 *
 * Normativa:
 *   - Ley 1581/2012 — datos sensibles — minimización
 *   - SAGRILAFT — debida diligencia sin exponer datos
 *   - SFC 025/2023 — KYC privacy-preserving
 *   - GDPR Art.5(1)(c) — minimización de datos
 *
 * TFM Reference: Fase 2 — Sprint 2.3 — ZKP KYC Proof
 */

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template KYCProof() {

    // ── Inputs privados ───────────────────────────────────────────
    signal input kycScore;      // 0-100 (90 = APPROVED)
    signal input birthYear;     // ej: 1990
    signal input documentHash;  // hash del documento KYC

    // ── Inputs públicos ───────────────────────────────────────────
    signal input minKycScore;   // umbral: 90
    signal input currentYear;   // año actual
    signal input minAge;        // edad mínima: 18
    signal input commitment;    // hash público de identidad

    // ── Output público ────────────────────────────────────────────
    signal output kycValid;

    // ── 1. Verificar KYC score >= minKycScore ────────────────────
    component scoreCheck = GreaterEqThan(8);
    scoreCheck.in[0] <== kycScore;
    scoreCheck.in[1] <== minKycScore;

    // ── 2. Verificar edad >= minAge ───────────────────────────────
    signal age;
    age <== currentYear - birthYear;

    component ageCheck = GreaterEqThan(8);
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;

    // ── 3. Verificar commitment = Poseidon(kycScore, birthYear, documentHash)
    // Vincula los inputs privados al commitment público
    // sin revelar los valores individuales
    component hasher = Poseidon(3);
    hasher.inputs[0] <== kycScore;
    hasher.inputs[1] <== birthYear;
    hasher.inputs[2] <== documentHash;

    // El commitment debe coincidir con el hash calculado
    commitment === hasher.out;

    // ── 4. Output: KYC válido si AMBAS condiciones se cumplen ─────
    kycValid <== scoreCheck.out * ageCheck.out;
}

component main {public [minKycScore, currentYear, minAge, commitment]} = KYCProof();