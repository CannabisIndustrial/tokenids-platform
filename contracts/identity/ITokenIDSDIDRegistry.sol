// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ITokenIDSDIDRegistry
 * @notice Interfaz del registro DID de TokenIDS
 * @dev Conforme a W3C DID Core 1.0 y ERC-1056
 *
 * Estándares implementados:
 *   - W3C DID Core 1.0 (https://www.w3.org/TR/did-core/)
 *   - W3C VC Data Model 2.0 (https://www.w3.org/TR/vc-data-model-2.0/)
 *   - ERC-1056: Ethereum Lightweight Identity
 *
 * Formato DID: did:tokenids:polygon:{chainId}:{address}
 * Ejemplo:      did:tokenids:polygon:80002:0xAbC...123
 *
 * Normativa:
 *   - Ley 527/1999 Colombia — validez firma electrónica
 *   - Ley 1581/2012 Colombia — protección datos personales
 *   - GDPR Art. 5(1)(c) — minimización de datos
 *
 * TFM Reference: Capítulo 4 — Fase 1 — Contratos de Identidad
 */
interface ITokenIDSDIDRegistry {

    // ─── Structs ──────────────────────────────────────────────────────────────

    /**
     * @notice Estructura de un DID registrado
     * @param didHash       Hash keccak256 del URI del DID
     * @param controller    Dirección que controla el DID
     * @param documentHash  Hash IPFS del documento DID completo (off-chain)
     * @param createdAt     Timestamp de creación (Unix)
     * @param updatedAt     Timestamp de última actualización
     * @param active        true si el DID está activo; false si fue desactivado
     */
    struct DIDRecord {
        bytes32 didHash;
        address controller;
        bytes32 documentHash;
        uint256 createdAt;
        uint256 updatedAt;
        bool    active;
    }

    /**
     * @notice Estructura de una Credencial Verificable (VC)
     * @param credentialId   Identificador único on-chain de la VC
     * @param subject        DID hash del sujeto de la credencial
     * @param credentialType Tipo: "KYCCredential" | "InvestorCredential" | "AssetOwnershipCredential"
     * @param dataHash       Hash IPFS del JSON-LD del VC completo (off-chain)
     * @param issuedAt       Timestamp de emisión
     * @param expiresAt      Timestamp de expiración (0 = no expira)
     * @param zkProof        Hash de la ZKP asociada (0x0 si no aplica)
     * @param revoked        true si la VC fue revocada
     */
    struct VerifiableCredential {
        bytes32 credentialId;
        bytes32 subject;
        string  credentialType;
        bytes32 dataHash;
        uint256 issuedAt;
        uint256 expiresAt;
        bytes32 zkProof;
        bool    revoked;
    }

    // ─── Errores (ERC-6093 custom errors) ────────────────────────────────────

    error DIDAlreadyExists(bytes32 didHash);
    error DIDNotFound(bytes32 didHash);
    error DIDNotActive(bytes32 didHash);
    error NotDIDController(address caller, bytes32 didHash);
    error CredentialNotFound(bytes32 credentialId);
    error CredentialAlreadyRevoked(bytes32 credentialId);
    error CredentialExpired(bytes32 credentialId, uint256 expiresAt);
    error InvalidDocumentHash();
    error InvalidSubject();
    error Unauthorized(address caller);

    // ─── Eventos ─────────────────────────────────────────────────────────────

    /**
     * @notice Emitido cuando se crea un nuevo DID
     * @param didHash      Hash del DID URI
     * @param controller   Dirección controladora
     * @param documentHash Hash del documento DID en IPFS
     * @param didUri       URI completo del DID (solo off-chain reference)
     */
    event DIDCreated(
        bytes32 indexed didHash,
        address indexed controller,
        bytes32         documentHash,
        string          didUri
    );

    /**
     * @notice Emitido cuando se actualiza el documento de un DID
     */
    event DIDUpdated(
        bytes32 indexed didHash,
        bytes32         newDocumentHash,
        uint256         updatedAt
    );

    /**
     * @notice Emitido cuando se desactiva un DID (derecho al olvido)
     */
    event DIDDeactivated(
        bytes32 indexed didHash,
        address indexed controller,
        uint256         deactivatedAt
    );

    /**
     * @notice Emitido cuando se emite una Credencial Verificable
     */
    event CredentialIssued(
        bytes32 indexed credentialId,
        bytes32 indexed subject,
        string          credentialType,
        bytes32         dataHash,
        uint256         expiresAt
    );

    /**
     * @notice Emitido cuando se revoca una Credencial Verificable
     */
    event CredentialRevoked(
        bytes32 indexed credentialId,
        address indexed revokedBy,
        uint256         revokedAt
    );

    // ─── Funciones principales ────────────────────────────────────────────────

    /**
     * @notice Crea un nuevo DID en el registro
     * @param didUri       URI completo del DID (did:tokenids:polygon:{chainId}:{addr})
     * @param documentHash Hash IPFS del documento DID
     * @return didHash     Hash keccak256 del URI registrado
     *
     * @dev Gas estimado: ~80.000 units en Polygon
     * @dev Normativa: W3C DID Core 1.0 Sección 8.1 (Create)
     */
    function createDID(
        string  calldata didUri,
        bytes32          documentHash
    ) external returns (bytes32 didHash);

    /**
     * @notice Actualiza el documento de un DID existente
     * @param didHash         Hash del DID a actualizar
     * @param newDocumentHash Nuevo hash IPFS del documento DID
     *
     * @dev Solo puede llamarlo el controller del DID
     * @dev Normativa: W3C DID Core 1.0 Sección 8.2 (Update)
     */
    function updateDID(
        bytes32 didHash,
        bytes32 newDocumentHash
    ) external;

    /**
     * @notice Desactiva un DID (operación irreversible)
     * @param didHash Hash del DID a desactivar
     *
     * @dev Implementa el derecho al olvido de GDPR Art. 17
     * @dev Los datos personales off-chain deben eliminarse por separado
     * @dev Normativa: W3C DID Core 1.0 Sección 8.4 (Deactivate)
     */
    function deactivateDID(bytes32 didHash) external;

    /**
     * @notice Emite una Credencial Verificable
     * @param subject        Hash del DID del sujeto
     * @param credentialType Tipo de credencial
     * @param dataHash       Hash IPFS del JSON-LD del VC
     * @param expiresAt      Timestamp de expiración (0 = sin expiración)
     * @param zkProof        Hash de la ZKP (bytes32(0) si no aplica)
     * @return credentialId  Identificador único de la credencial
     *
     * @dev Gas estimado: ~120.000 units en Polygon
     * @dev Solo emisores con rol ISSUER_ROLE pueden llamar esta función
     * @dev Normativa: W3C VC Data Model 2.0 Sección 4 (Verifiable Credentials)
     */
    function issueCredential(
        bytes32         subject,
        string calldata credentialType,
        bytes32         dataHash,
        uint256         expiresAt,
        bytes32         zkProof
    ) external returns (bytes32 credentialId);

    /**
     * @notice Revoca una Credencial Verificable
     * @param credentialId ID de la credencial a revocar
     *
     * @dev Solo el emisor original o un ISSUER_ROLE puede revocar
     * @dev Normativa: W3C VC Data Model 2.0 Sección 7 (Revocation)
     */
    function revokeCredential(bytes32 credentialId) external;

    // ─── Funciones de lectura (sin gas) ──────────────────────────────────────

    /**
     * @notice Verifica si una credencial es válida en el momento actual
     * @param credentialId ID de la credencial a verificar
     * @return valid       true si está activa, no revocada y no expirada
     *
     * @dev Función de lectura — no consume gas cuando se llama off-chain
     * @dev Es llamada por ERC-3643 ComplianceManager antes de cada transferencia
     */
    function verifyCredential(bytes32 credentialId) external view returns (bool valid);

    /**
     * @notice Resuelve un DID y devuelve su registro completo
     * @param didHash Hash del DID a resolver
     * @return record Estructura DIDRecord con todos los datos
     *
     * @dev Normativa: W3C DID Core 1.0 Sección 8.3 (Read/Resolve)
     */
    function resolveDID(bytes32 didHash) external view returns (DIDRecord memory record);

    /**
     * @notice Devuelve una credencial por su ID
     * @param credentialId ID de la credencial
     * @return vc          Estructura VerifiableCredential
     */
    function getCredential(bytes32 credentialId)
        external view returns (VerifiableCredential memory vc);

    /**
     * @notice Devuelve el DID hash asociado a una dirección Ethereum
     * @param controller Dirección a consultar
     * @return didHash   Hash del DID de esa dirección (0x0 si no tiene)
     */
    function getDIDByAddress(address controller)
        external view returns (bytes32 didHash);
}