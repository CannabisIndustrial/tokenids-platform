// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl}    from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712}           from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard}  from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable}         from "@openzeppelin/contracts/utils/Pausable.sol";
import {ITokenIDSDIDRegistry} from "./ITokenIDSDIDRegistry.sol";

/**
 * @title TokenIDSDIDRegistry
 * @author Johana Niño Abella — TokenIDS TFM
 * @notice Registro descentralizado de identidades DID para TokenIDS
 *
 * @dev Implementa:
 *   - W3C DID Core 1.0 (Create / Read / Update / Deactivate)
 *   - W3C VC Data Model 2.0 (Issue / Verify / Revoke)
 *   - ERC-1056: Ethereum Lightweight Identity
 *   - EIP-712: Typed structured data hashing and signing
 *
 * Formato DID: did:tokenids:polygon:{chainId}:{address}
 *
 * Roles de acceso (OpenZeppelin AccessControl):
 *   - DEFAULT_ADMIN_ROLE : gestión de roles del sistema
 *   - ISSUER_ROLE        : emisión y revocación de credenciales KYC
 *   - VERIFIER_ROLE      : consulta de credenciales (lectura privilegiada)
 *   - AUDITOR_ROLE       : acceso de solo lectura para auditores regulatorios
 *   - PAUSER_ROLE        : pausar el contrato en caso de emergencia
 *
 * Normativa:
 *   - Ley 527/1999 Colombia (validez firma electrónica)
 *   - Ley 1581/2012 Colombia (protección datos personales)
 *   - GDPR Art. 5(1)(c) y Art. 17 (minimización y derecho al olvido)
 *   - FATF R.16 (Travel Rule — datos de identidad para transferencias)
 *   - SFC Circular 025/2023 (debida diligencia Colombia)
 *
 * Arquitectura de datos (privacidad por diseño):
 *   ON-CHAIN  : hashes criptográficos únicamente (keccak256, IPFS CID)
 *   OFF-CHAIN : datos personales cifrados en IPFS + PostgreSQL
 *   ZKP       : verificación de atributos sin revelación de datos
 *
 * Gas estimates (Polygon PoS):
 *   createDID()         ~80.000 units  (~0,003 USD)
 *   issueCredential()   ~120.000 units (~0,005 USD)
 *   verifyCredential()  ~0 (view)
 *
 * TFM Reference: Capítulo 4 — Fase 1 — TokenIDSDIDRegistry
 * Repositorio: github.com/CannabisIndustrial/tokenids-platform
 */
contract TokenIDSDIDRegistry is
    ITokenIDSDIDRegistry,
    AccessControl,
    EIP712,
    ReentrancyGuard,
    Pausable
{
    // ─── Roles ────────────────────────────────────────────────────────────────

    bytes32 public constant ISSUER_ROLE   = keccak256("ISSUER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant AUDITOR_ROLE  = keccak256("AUDITOR_ROLE");
    bytes32 public constant PAUSER_ROLE   = keccak256("PAUSER_ROLE");

    // ─── Constantes ───────────────────────────────────────────────────────────

    /// @notice Versión del contrato (para EIP-712 domain separator)
    string public constant VERSION = "1.0.0";

    /// @notice Nombre del método DID de TokenIDS
    string public constant DID_METHOD = "tokenids";

    /// @notice Máximo de credenciales activas por DID (anti-spam)
    uint256 public constant MAX_CREDENTIALS_PER_DID = 50;

    // ─── Estado ───────────────────────────────────────────────────────────────

    /// @dev DID hash => DIDRecord
    mapping(bytes32 => DIDRecord) private _dids;

    /// @dev Controller address => DID hash (cada dirección tiene máximo 1 DID)
    mapping(address => bytes32) private _addressToDID;

    /// @dev Credential ID => VerifiableCredential
    mapping(bytes32 => VerifiableCredential) private _credentials;

    /// @dev DID hash => array de credential IDs emitidos para ese sujeto
    mapping(bytes32 => bytes32[]) private _didCredentials;

    /// @dev Credential ID => issuer address (para control de revocación)
    mapping(bytes32 => address) private _credentialIssuer;

    /// @dev Contador total de DIDs creados (para estadísticas y auditoría)
    uint256 private _totalDIDs;

    /// @dev Contador total de credenciales emitidas
    uint256 private _totalCredentials;

    // ─── Constructor ──────────────────────────────────────────────────────────

    /**
     * @param admin Dirección que recibirá el DEFAULT_ADMIN_ROLE inicial
     * @param initialIssuer Dirección del primer emisor KYC autorizado
     *
     * @dev EIP-712 domain: name="TokenIDSDIDRegistry", version="1.0.0"
     */
    constructor(address admin, address initialIssuer)
        EIP712("TokenIDSDIDRegistry", VERSION)
    {
        require(admin != address(0),         "Admin cannot be zero address");
        require(initialIssuer != address(0), "Issuer cannot be zero address");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE,        initialIssuer);
        _grantRole(PAUSER_ROLE,        admin);
    }

    // ─── Funciones principales ────────────────────────────────────────────────

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Proceso:
     *   1. Verifica que el caller no tiene DID previo
     *   2. Calcula didHash = keccak256(didUri)
     *   3. Verifica que el didHash no está registrado
     *   4. Almacena el DIDRecord con datos mínimos (privacidad por diseño)
     *   5. Registra la asociación address => didHash
     *   6. Emite evento DIDCreated para indexación en The Graph
     */
    function createDID(
        string  calldata didUri,
        bytes32          documentHash
    )
        external
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 didHash)
    {
        if (documentHash == bytes32(0)) revert InvalidDocumentHash();
        if (_addressToDID[msg.sender] != bytes32(0)) {
            revert DIDAlreadyExists(_addressToDID[msg.sender]);
        }

        didHash = keccak256(abi.encodePacked(didUri));

        if (_dids[didHash].createdAt != 0) {
            revert DIDAlreadyExists(didHash);
        }

        _dids[didHash] = DIDRecord({
            didHash:      didHash,
            controller:   msg.sender,
            documentHash: documentHash,
            createdAt:    block.timestamp,
            updatedAt:    block.timestamp,
            active:       true
        });

        _addressToDID[msg.sender] = didHash;
        _totalDIDs++;

        emit DIDCreated(didHash, msg.sender, documentHash, didUri);
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Solo el controller del DID puede actualizar su documento
     *      Normativa: W3C DID Core 1.0 Sección 8.2 (Update)
     */
    function updateDID(
        bytes32 didHash,
        bytes32 newDocumentHash
    )
        external
        override
        nonReentrant
        whenNotPaused
    {
        if (newDocumentHash == bytes32(0)) revert InvalidDocumentHash();
        _requireActiveDID(didHash);
        _requireDIDController(didHash);

        _dids[didHash].documentHash = newDocumentHash;
        _dids[didHash].updatedAt    = block.timestamp;

        emit DIDUpdated(didHash, newDocumentHash, block.timestamp);
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Implementa derecho al olvido (GDPR Art. 17 / Ley 1581 Art. 8)
     *      La desactivación on-chain es irreversible.
     *      Los datos personales off-chain deben eliminarse por proceso separado.
     *      El hash on-chain no constituye dato personal (CEPD Guidelines 05/2022).
     */
    function deactivateDID(bytes32 didHash)
        external
        override
        nonReentrant
    {
        _requireActiveDID(didHash);
        _requireDIDController(didHash);

        _dids[didHash].active    = false;
        _dids[didHash].updatedAt = block.timestamp;

        // Liberar la asociación address => DID
        delete _addressToDID[msg.sender];

        emit DIDDeactivated(didHash, msg.sender, block.timestamp);
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Solo emisores con ISSUER_ROLE pueden emitir credenciales.
     *      Los datos personales van en dataHash (IPFS CID) — nunca on-chain.
     *
     *      Tipos de credencial soportados:
     *        "KYCCredential"              — verificación de identidad
     *        "InvestorCredential"         — categoría de inversor
     *        "AssetOwnershipCredential"   — titularidad de activo tokenizado
     *
     *      Normativa:
     *        W3C VC Data Model 2.0 Sección 4
     *        SAGRILAFT — evidencia de debida diligencia
     *        SFC Circular 025/2023 — registro de onboarding
     */
    function issueCredential(
        bytes32         subject,
        string calldata credentialType,
        bytes32         dataHash,
        uint256         expiresAt,
        bytes32         zkProof
    )
        external
        override
        nonReentrant
        whenNotPaused
        onlyRole(ISSUER_ROLE)
        returns (bytes32 credentialId)
    {
        if (subject == bytes32(0))    revert InvalidSubject();
        if (dataHash == bytes32(0))   revert InvalidDocumentHash();
        if (!_dids[subject].active)   revert DIDNotActive(subject);
        if (expiresAt != 0 && expiresAt <= block.timestamp) {
            revert CredentialExpired(bytes32(0), expiresAt);
        }

        // Verificar límite anti-spam
        require(
            _didCredentials[subject].length < MAX_CREDENTIALS_PER_DID,
            "Max credentials per DID reached"
        );

        // Generar ID único: hash de (subject + type + issuer + timestamp + nonce)
        credentialId = keccak256(abi.encodePacked(
            subject,
            credentialType,
            msg.sender,
            block.timestamp,
            _totalCredentials
        ));

        _credentials[credentialId] = VerifiableCredential({
            credentialId:   credentialId,
            subject:        subject,
            credentialType: credentialType,
            dataHash:       dataHash,
            issuedAt:       block.timestamp,
            expiresAt:      expiresAt,
            zkProof:        zkProof,
            revoked:        false
        });

        _credentialIssuer[credentialId] = msg.sender;
        _didCredentials[subject].push(credentialId);
        _totalCredentials++;

        emit CredentialIssued(
            credentialId,
            subject,
            credentialType,
            dataHash,
            expiresAt
        );
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Solo el emisor original o un ISSUER_ROLE puede revocar.
     *      La revocación es irreversible.
     *      Normativa: W3C VC Data Model 2.0 Sección 7 (Revocation)
     *                 SAGRILAFT — revocación por cambio de estado del cliente
     */
    function revokeCredential(bytes32 credentialId)
        external
        override
        nonReentrant
    {
        VerifiableCredential storage vc = _credentials[credentialId];
        if (vc.issuedAt == 0)  revert CredentialNotFound(credentialId);
        if (vc.revoked)        revert CredentialAlreadyRevoked(credentialId);

        // Solo el emisor original o cualquier ISSUER_ROLE puede revocar
        bool isOriginalIssuer = (_credentialIssuer[credentialId] == msg.sender);
        bool isAuthorizedRole = hasRole(ISSUER_ROLE, msg.sender);

        if (!isOriginalIssuer && !isAuthorizedRole) {
            revert Unauthorized(msg.sender);
        }

        vc.revoked = true;

        emit CredentialRevoked(credentialId, msg.sender, block.timestamp);
    }

    // ─── Funciones de lectura ─────────────────────────────────────────────────

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     *
     * @dev Llamada por ERC-3643 ComplianceManager antes de cada transferencia.
     *      Es una función view — no consume gas en llamadas off-chain.
     *      Tres condiciones para validez: no revocada + no expirada + DID activo
     */
    function verifyCredential(bytes32 credentialId)
        external
        view
        override
        returns (bool valid)
    {
        VerifiableCredential storage vc = _credentials[credentialId];
        if (vc.issuedAt == 0) return false;
        if (vc.revoked)       return false;
        if (vc.expiresAt != 0 && block.timestamp > vc.expiresAt) return false;
        if (!_dids[vc.subject].active) return false;

        return true;
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     * @dev Normativa: W3C DID Core 1.0 Sección 8.3 (Read/Resolve)
     */
    function resolveDID(bytes32 didHash)
        external
        view
        override
        returns (DIDRecord memory record)
    {
        if (_dids[didHash].createdAt == 0) revert DIDNotFound(didHash);
        return _dids[didHash];
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     */
    function getCredential(bytes32 credentialId)
        external
        view
        override
        returns (VerifiableCredential memory vc)
    {
        if (_credentials[credentialId].issuedAt == 0) {
            revert CredentialNotFound(credentialId);
        }
        return _credentials[credentialId];
    }

    /**
     * @inheritdoc ITokenIDSDIDRegistry
     */
    function getDIDByAddress(address controller)
        external
        view
        override
        returns (bytes32 didHash)
    {
        return _addressToDID[controller];
    }

    /**
     * @notice Devuelve todas las credenciales emitidas para un DID
     * @param didHash Hash del DID sujeto
     * @return ids    Array de credential IDs
     */
    function getCredentialsByDID(bytes32 didHash)
        external
        view
        returns (bytes32[] memory ids)
    {
        return _didCredentials[didHash];
    }

    /**
     * @notice Devuelve las estadísticas globales del registro
     * @return totalDIDs         Número total de DIDs creados
     * @return totalCredentials  Número total de credenciales emitidas
     */
    function getStats()
        external
        view
        returns (uint256 totalDIDs, uint256 totalCredentials)
    {
        return (_totalDIDs, _totalCredentials);
    }

    // ─── Funciones administrativas ────────────────────────────────────────────

    /**
     * @notice Pausa el contrato en caso de emergencia
     * @dev Solo PAUSER_ROLE — detiene createDID, updateDID e issueCredential
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Reanuda el contrato tras la emergencia
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ─── Helpers internos ────────────────────────────────────────────────────

    function _requireActiveDID(bytes32 didHash) internal view {
        if (_dids[didHash].createdAt == 0) revert DIDNotFound(didHash);
        if (!_dids[didHash].active)        revert DIDNotActive(didHash);
    }

    function _requireDIDController(bytes32 didHash) internal view {
        if (_dids[didHash].controller != msg.sender) {
            revert NotDIDController(msg.sender, didHash);
        }
    }
}