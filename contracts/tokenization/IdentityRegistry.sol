// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl}   from "@openzeppelin/contracts/access/AccessControl.sol";
import {ITokenIDSDIDRegistry} from "../identity/ITokenIDSDIDRegistry.sol";

/**
 * @title IdentityRegistry
 * @notice Registro de identidades verificadas para ERC-3643
 * @dev Integra el TokenIDSDIDRegistry (DID + VC) con el
 *      sistema de compliance de activos tokenizados.
 *
 *      Flujo de verificación:
 *      1. Wallet tiene DID registrado en TokenIDSDIDRegistry
 *      2. DID tiene VC KYCCredential válida y no expirada
 *      3. IdentityRegistry marca la wallet como "verified"
 *      4. ERC-3643 ComplianceManager consulta este registro
 *         antes de ejecutar cada transferencia
 *
 * Normativa:
 *   - SAGRILAFT — debida diligencia del cliente
 *   - SFC Circular 025/2023 — KYC para activos digitales
 *   - FATF R.16 — identificación de originador y beneficiario
 *
 * TFM Reference: Fase 2 — Sprint 2.1 — IdentityRegistry
 */
contract IdentityRegistry is AccessControl {

    bytes32 public constant REGISTRAR_ROLE =
        keccak256("REGISTRAR_ROLE");
    bytes32 public constant AGENT_ROLE =
        keccak256("AGENT_ROLE");

    // ─── Estado ───────────────────────────────────────────────

    /// @notice Contrato DID Registry de TokenIDS
    ITokenIDSDIDRegistry public immutable didRegistry;

    /// @dev wallet => verified
    mapping(address => bool) private _verified;

    /// @dev wallet => credentialId KYC que la verificó
    mapping(address => bytes32) private _kycCredential;

    /// @dev wallet => timestamp de verificación
    mapping(address => uint256) private _verifiedAt;

    uint256 private _totalVerified;

    // ─── Eventos ──────────────────────────────────────────────

    event IdentityRegistered(
        address indexed wallet,
        bytes32 indexed kycCredentialId,
        uint256         verifiedAt
    );

    event IdentityRemoved(
        address indexed wallet,
        uint256         removedAt
    );

    // ─── Errores ──────────────────────────────────────────────

    error WalletAlreadyVerified(address wallet);
    error WalletNotVerified(address wallet);
    error InvalidKYCCredential(bytes32 credentialId);
    error NoDIDRegistered(address wallet);

    // ─── Constructor ──────────────────────────────────────────

    constructor(address admin, address didRegistryAddr) {
        require(admin != address(0), "Admin: zero address");
        require(didRegistryAddr != address(0), "DID: zero address");

        didRegistry = ITokenIDSDIDRegistry(didRegistryAddr);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    // ─── Funciones principales ────────────────────────────────

    /**
     * @notice Registra una wallet como identidad verificada
     * @param wallet         Dirección a verificar
     * @param kycCredentialId ID de la VC KYC en TokenIDSDIDRegistry
     *
     * @dev Verifica que:
     *   1. La wallet tiene DID registrado
     *   2. La VC KYC es válida (no revocada, no expirada)
     *   3. La wallet no está ya verificada
     *
     * Normativa: SAGRILAFT — evidencia de debida diligencia
     */
    function registerIdentity(
        address wallet,
        bytes32 kycCredentialId
    )
        external
        onlyRole(REGISTRAR_ROLE)
    {
        if (_verified[wallet]) revert WalletAlreadyVerified(wallet);

        // Verificar que la wallet tiene DID registrado
        bytes32 didHash = didRegistry.getDIDByAddress(wallet);
        if (didHash == bytes32(0)) revert NoDIDRegistered(wallet);

        // Verificar que la VC KYC es válida on-chain
        bool credentialValid = didRegistry.verifyCredential(
            kycCredentialId
        );
        if (!credentialValid) revert InvalidKYCCredential(kycCredentialId);

        _verified[wallet]       = true;
        _kycCredential[wallet]  = kycCredentialId;
        _verifiedAt[wallet]     = block.timestamp;
        _totalVerified++;

        emit IdentityRegistered(wallet, kycCredentialId, block.timestamp);
    }

    /**
     * @notice Elimina la verificación de una wallet
     * @dev Implementa derecho al olvido — Ley 1581/2012 Art. 8
     *      y GDPR Art. 17 aplicado a la capa de compliance
     */
    function removeIdentity(address wallet)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        if (!_verified[wallet]) revert WalletNotVerified(wallet);

        delete _verified[wallet];
        delete _kycCredential[wallet];
        delete _verifiedAt[wallet];
        _totalVerified--;

        emit IdentityRemoved(wallet, block.timestamp);
    }

    // ─── Funciones de lectura ─────────────────────────────────

    /**
     * @notice Verifica si una wallet tiene identidad registrada
     * @dev Llamado por ComplianceManager antes de cada transferencia
     *      También re-verifica la VC on-chain para detectar revocaciones
     */
    function isVerified(address wallet)
        external
        view
        returns (bool)
    {
        if (!_verified[wallet]) return false;

        // Re-verificar la VC on-chain — detecta revocaciones posteriores
        bytes32 credId = _kycCredential[wallet];
        if (credId == bytes32(0)) return false;

        return didRegistry.verifyCredential(credId);
    }

    /**
     * @notice Devuelve el ID de la VC KYC de una wallet
     */
    function getKYCCredential(address wallet)
        external
        view
        returns (bytes32)
    {
        return _kycCredential[wallet];
    }

    /**
     * @notice Devuelve el timestamp de verificación de una wallet
     */
    function getVerifiedAt(address wallet)
        external
        view
        returns (uint256)
    {
        return _verifiedAt[wallet];
    }

    /**
     * @notice Número total de identidades verificadas
     */
    function totalVerified() external view returns (uint256) {
        return _totalVerified;
    }
}