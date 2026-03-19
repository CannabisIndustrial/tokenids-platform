// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20}            from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControl}    from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable}         from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard}  from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ITokenIDSAsset}   from "./ITokenIDSAsset.sol";
import {ComplianceManager} from "./ComplianceManager.sol";
import {IdentityRegistry}  from "./IdentityRegistry.sol";

/**
 * @title TokenIDSAsset
 * @notice Token ERC-20 con compliance ERC-3643 para activos reales
 * @dev Cada instancia representa UN activo tokenizado.
 *
 *      Extensiones sobre ERC-20 estándar:
 *        - Todas las transferencias pasan por ComplianceManager
 *        - Emisor y receptor deben tener KYC activo (ERC-3643)
 *        - Travel Rule alert si valor > 1.000 USD (FATF R.16)
 *        - SAGRILAFT alert si valor > 10.000 USD (Colombia)
 *
 *      Gas estimates (Polygon PoS):
 *        tokenizeAsset():          ~150.000 units (~0,006 USD)
 *        transferWithCompliance(): ~80.000 units  (~0,003 USD)
 *
 * Normativa:
 *   - ERC-3643 T-REX (eips.ethereum.org/EIPS/eip-3643)
 *   - FATF R.16 (rev. junio 2025) — Travel Rule
 *   - SFC Circular 025/2023 — activos digitales Colombia
 *   - Decreto 2555/2010 — mercado de valores Colombia
 *   - SAGRILAFT — sistema AML Colombia
 *
 * TFM Reference: Fase 2 — Sprint 2.1 — TokenIDSAsset ERC-3643
 */
contract TokenIDSAsset is
    ITokenIDSAsset,
    ERC20,
    AccessControl,
    Pausable,
    ReentrancyGuard
{
    // ─── Roles ────────────────────────────────────────────────

    bytes32 public constant ASSET_MANAGER_ROLE =
        keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE =
        keccak256("PAUSER_ROLE");

    // ─── Estado ───────────────────────────────────────────────

    ComplianceManager public immutable complianceManager;

    AssetMetadata private _asset;
    bool          private _tokenized;

    // ─── Constructor ──────────────────────────────────────────

    /**
     * @param name_                Nombre del token (ej: "Casa Bogota 001")
     * @param symbol_              Simbolo del token (ej: "TKIDS-CB001")
     * @param admin                Administrador del contrato
     * @param complianceManagerAddr Direccion del ComplianceManager
     */
    constructor(
        string memory name_,
        string memory symbol_,
        address       admin,
        address       complianceManagerAddr
    )
        ERC20(name_, symbol_)
    {
        require(admin != address(0),              "Admin: zero address");
        require(complianceManagerAddr != address(0), "CM: zero address");

        complianceManager = ComplianceManager(complianceManagerAddr);

        _grantRole(DEFAULT_ADMIN_ROLE,   admin);
        _grantRole(ASSET_MANAGER_ROLE,   admin);
        _grantRole(PAUSER_ROLE,          admin);
    }

    // ─── Funciones principales ────────────────────────────────

    /**
     * @inheritdoc ITokenIDSAsset
     * @dev Solo puede tokenizarse una vez por contrato.
     *      Los tokens se emiten al msg.sender (propietario inicial).
     *
     * Normativa:
     *   - SFC 025/2023 — tokenizacion de activos digitales
     *   - Decreto 2555/2010 — oferta de valores Colombia
     */
    function tokenizeAsset(
        bytes32         assetId,
        string calldata assetType,
        uint256         valueUSD,
        uint256         totalSupply_,
        bytes32         documentHash
    )
        external
        override
        onlyRole(ASSET_MANAGER_ROLE)
        whenNotPaused
        nonReentrant
    {
        require(!_tokenized,                      "Asset: already tokenized");
        require(assetId != bytes32(0),            "Asset: invalid ID");
        require(bytes(assetType).length > 0,      "Asset: type required");
        require(valueUSD > 0,                     "Asset: value must be > 0");
        require(totalSupply_ > 0,                 "Asset: supply must be > 0");
        require(documentHash != bytes32(0),       "Asset: document required");

        _asset = AssetMetadata({
            assetId:      assetId,
            assetType:    assetType,
            valueUSD:     valueUSD,
            documentHash: documentHash,
            active:       true
        });

        _tokenized = true;
        _mint(msg.sender, totalSupply_);

        emit AssetTokenized(assetId, msg.sender, totalSupply_, valueUSD);
    }

    /**
     * @inheritdoc ITokenIDSAsset
     * @dev Reemplaza la transferencia ERC-20 estandar.
     *      Verifica compliance ANTES de ejecutar la transferencia.
     *
     * Normativa:
     *   - ERC-3643 seccion 4 — transferencias condicionadas
     *   - FATF R.16 — Travel Rule en transferencias >1.000 USD
     */
    function transferWithCompliance(
        address to,
        uint256 amount
    )
        external
        override
        nonReentrant
        whenNotPaused
        returns (bool)
    {
        if (amount == 0) revert InvalidAmount();
        if (balanceOf(msg.sender) < amount) {
            revert InsufficientBalance(msg.sender, balanceOf(msg.sender));
        }

        uint256 recipientBalance = balanceOf(to);

        // Verificacion compliance — revierte si no cumple
        complianceManager.checkCompliance(
            msg.sender,
            to,
            amount,
            recipientBalance
        );

        // Calcular si aplica Travel Rule (FATF R.16)
        uint256 valueUSD = amount * complianceManager.tokenPriceUSD();
        bool travelRuleRequired = valueUSD >=
            complianceManager.travelRuleThresholdUSD();

        // Ejecutar transferencia ERC-20 estandar
        _transfer(msg.sender, to, amount);

        emit ComplianceTransfer(msg.sender, to, amount, travelRuleRequired);

        return true;
    }

    // ─── Funciones de lectura ─────────────────────────────────

    /**
     * @inheritdoc ITokenIDSAsset
     */
    function canTransfer(
        address from,
        address to,
        uint256 amount
    )
        external
        view
        override
        returns (bool compliant)
    {
        if (!_asset.active)            return false;
        if (balanceOf(from) < amount)  return false;

        // Verificar KYC via IdentityRegistry
        IdentityRegistry ir = IdentityRegistry(
            address(complianceManager.identityRegistry())
        );
        if (!ir.isVerified(from)) return false;
        if (!ir.isVerified(to))   return false;

        // Verificar blacklist
        if (complianceManager.isBlacklisted(from)) return false;
        if (complianceManager.isBlacklisted(to))   return false;

        // Verificar limite de balance
        uint256 maxBal = complianceManager.maxBalancePerInvestor();
        if (maxBal > 0 && balanceOf(to) + amount > maxBal) return false;

        return true;
    }

    /**
     * @inheritdoc ITokenIDSAsset
     */
    function getAssetMetadata()
        external
        view
        override
        returns (AssetMetadata memory)
    {
        return _asset;
    }

    /**
     * @inheritdoc ITokenIDSAsset
     */
    function pricePerToken() external view override returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) return 0;
        return _asset.valueUSD / supply;
    }

    // ─── Override transfer estandar ERC-20 ───────────────────

    /**
     * @notice Bloquea la funcion transfer() estandar de ERC-20
     * @dev En ERC-3643, toda transferencia DEBE ir por
     *      transferWithCompliance(). El transfer() estandar
     *      queda deshabilitado para garantizar el compliance.
     */
    function transfer(address, uint256)
        public
        pure
        override
        returns (bool)
    {
        revert("Use transferWithCompliance()");
    }

    function transferFrom(address, address, uint256)
        public
        pure
        override
        returns (bool)
    {
        revert("Use transferWithCompliance()");
    }

    // ─── Control de emergencia ────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}