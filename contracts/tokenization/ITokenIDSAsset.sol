// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ITokenIDSAsset
 * @notice Interfaz del token de activo tokenizado de TokenIDS
 * @dev Conforme a ERC-3643 T-REX (Token for Regulated EXchanges)
 *      EIP: https://eips.ethereum.org/EIPS/eip-3643
 *
 * Normativa:
 *   - ERC-3643 T-REX — activos regulados on-chain
 *   - Ley 527/1999 Colombia — validez transacciones electrónicas
 *   - SFC Circular 025/2023 — activos digitales Colombia
 *   - FATF R.16 — Travel Rule para transferencias >1.000 USD
 *
 * TFM Reference: Fase 2 — Sprint 2.1 — ERC-3643 Interface
 */
interface ITokenIDSAsset {

    // ─── Structs ──────────────────────────────────────────────

    /**
     * @notice Metadatos del activo tokenizado
     * @param assetId       Identificador único del activo
     * @param assetType     Tipo: "INMUEBLE" | "VEHICULO" | "OTRO"
     * @param valueUSD      Valor del activo en USD (sin decimales)
     * @param documentHash  Hash IPFS del expediente del activo
     * @param active        true si el activo está activo
     */
    struct AssetMetadata {
        bytes32 assetId;
        string  assetType;
        uint256 valueUSD;
        bytes32 documentHash;
        bool    active;
    }

    // ─── Errores ──────────────────────────────────────────────

    error TransferNotCompliant(address from, address to);
    error IdentityNotVerified(address wallet);
    error AssetNotActive(bytes32 assetId);
    error InsufficientBalance(address wallet, uint256 balance);
    error Unauthorized(address caller);
    error InvalidAmount();

    // ─── Eventos ──────────────────────────────────────────────

    /**
     * @notice Emitido cuando se mintean tokens de un activo
     */
    event AssetTokenized(
        bytes32 indexed assetId,
        address indexed owner,
        uint256         totalSupply,
        uint256         valueUSD
    );

    /**
     * @notice Emitido cuando una transferencia pasa el compliance
     */
    event ComplianceTransfer(
        address indexed from,
        address indexed to,
        uint256         amount,
        bool            travelRuleRequired
    );

    // ─── Funciones principales ────────────────────────────────

    /**
     * @notice Tokeniza un activo real emitiendo tokens ERC-20
     * @param assetId      ID único del activo
     * @param assetType    Tipo de activo
     * @param valueUSD     Valor en USD
     * @param totalSupply  Número total de tokens a emitir
     * @param documentHash Hash IPFS del expediente
     */
    function tokenizeAsset(
        bytes32         assetId,
        string calldata assetType,
        uint256         valueUSD,
        uint256         totalSupply,
        bytes32         documentHash
    ) external;

    /**
     * @notice Transferencia de tokens con verificación de compliance
     * @dev Verifica identidad KYC de emisor y receptor antes de ejecutar
     *      Si el valor > 1.000 USD emite evento Travel Rule (FATF R.16)
     */
    function transferWithCompliance(
        address to,
        uint256 amount
    ) external returns (bool);

    /**
     * @notice Verifica si una transferencia es conforme a las reglas
     * @return compliant true si la transferencia puede ejecutarse
     */
    function canTransfer(
        address from,
        address to,
        uint256 amount
    ) external view returns (bool compliant);

    /**
     * @notice Devuelve los metadatos del activo tokenizado
     */
    function getAssetMetadata()
        external view returns (AssetMetadata memory);

    /**
     * @notice Precio por token en USD (valueUSD / totalSupply)
     */
    function pricePerToken() external view returns (uint256);
}