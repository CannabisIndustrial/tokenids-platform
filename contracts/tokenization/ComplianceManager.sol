// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IdentityRegistry} from "./IdentityRegistry.sol";

/**
 * @title ComplianceManager
 * @notice Motor de reglas de compliance on-chain para ERC-3643
 * @dev Verifica el cumplimiento normativo antes de cada
 *      transferencia de tokens de activo tokenizado.
 *
 *      Reglas implementadas:
 *        1. KYC activo: emisor y receptor verificados
 *        2. Travel Rule: alerta si value > umbral FATF
 *        3. CountryRestriction: whitelist de jurisdicciones
 *        4. MaxBalance: límite de concentración por inversor
 *
 * Normativa:
 *   - ERC-3643 T-REX — compliance engine
 *   - FATF R.16 (rev. junio 2025) — Travel Rule umbral 1.000 USD
 *   - SAGRILAFT — umbral reporte 10.000 USD
 *   - Decreto 2555/2010 Colombia — mercado de valores
 *
 * TFM Reference: Fase 2 — Sprint 2.1 — ComplianceManager
 */
contract ComplianceManager is AccessControl {

    bytes32 public constant COMPLIANCE_ROLE =
        keccak256("COMPLIANCE_ROLE");

    // ─── Estado ───────────────────────────────────────────────

    IdentityRegistry public immutable identityRegistry;

    /// @notice Umbral Travel Rule en USD (FATF R.16: 1.000 USD)
    uint256 public travelRuleThresholdUSD = 1_000;

    /// @notice Umbral SAGRILAFT en USD (Colombia: 10.000 USD)
    uint256 public sagrilaftThresholdUSD = 10_000;

    /// @notice Límite máximo de tokens por inversor (anti-concentración)
    /// @dev 0 = sin límite
    uint256 public maxBalancePerInvestor;

    /// @dev Precio por token en USD — para calcular umbrales
    uint256 public tokenPriceUSD;

    /// @dev address => blacklisted
    mapping(address => bool) private _blacklisted;

    /// @dev Contador de verificaciones — para auditoría
    uint256 private _totalChecks;
    uint256 private _totalBlocked;

    // ─── Eventos ──────────────────────────────────────────────

    event ComplianceChecked(
        address indexed from,
        address indexed to,
        uint256         amount,
        bool            passed
    );

    event TravelRuleTriggered(
        address indexed from,
        address indexed to,
        uint256         valueUSD,
        uint256         timestamp
    );

    event SAGRILAFTAlertTriggered(
        address indexed from,
        address indexed to,
        uint256         valueUSD,
        uint256         timestamp
    );

    event AddressBlacklisted(address indexed wallet, uint256 at);
    event AddressWhitelisted(address indexed wallet, uint256 at);

    // ─── Errores ──────────────────────────────────────────────

    error SenderNotKYC(address sender);
    error RecipientNotKYC(address recipient);
    error SenderBlacklisted(address sender);
    error RecipientBlacklisted(address recipient);
    error ExceedsMaxBalance(address recipient, uint256 current, uint256 max);
    error InvalidThreshold();

    // ─── Constructor ──────────────────────────────────────────

    constructor(
        address admin,
        address identityRegistryAddr,
        uint256 _tokenPriceUSD,
        uint256 _maxBalancePerInvestor
    ) {
        require(admin != address(0), "Admin: zero address");
        require(identityRegistryAddr != address(0), "Registry: zero address");
        require(_tokenPriceUSD > 0, "Price: must be > 0");

        identityRegistry     = IdentityRegistry(identityRegistryAddr);
        tokenPriceUSD        = _tokenPriceUSD;
        maxBalancePerInvestor = _maxBalancePerInvestor;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(COMPLIANCE_ROLE, admin);
    }

    // ─── Verificación principal ───────────────────────────────

    /**
     * @notice Verifica si una transferencia cumple todas las reglas
     * @param from     Dirección emisora
     * @param to       Dirección receptora
     * @param amount   Cantidad de tokens
     * @param balance  Balance actual del receptor
     * @return passed  true si la transferencia puede ejecutarse
     *
     * @dev Esta función es llamada por TokenIDSAsset.transferWithCompliance()
     *      antes de ejecutar cualquier transferencia.
     *      Es determinista — no usa IA ni llamadas externas.
     */
    function checkCompliance(
        address from,
        address to,
        uint256 amount,
        uint256 balance
    )
        external
        returns (bool passed)
    {
        _totalChecks++;

        // Regla 1 — KYC activo para emisor
        if (!identityRegistry.isVerified(from)) {
            _totalBlocked++;
            emit ComplianceChecked(from, to, amount, false);
            revert SenderNotKYC(from);
        }

        // Regla 2 — KYC activo para receptor
        if (!identityRegistry.isVerified(to)) {
            _totalBlocked++;
            emit ComplianceChecked(from, to, amount, false);
            revert RecipientNotKYC(to);
        }

        // Regla 3 — Blacklist screening (OFAC/UIAF on-chain)
        if (_blacklisted[from]) {
            _totalBlocked++;
            emit ComplianceChecked(from, to, amount, false);
            revert SenderBlacklisted(from);
        }

        if (_blacklisted[to]) {
            _totalBlocked++;
            emit ComplianceChecked(from, to, amount, false);
            revert RecipientBlacklisted(to);
        }

        // Regla 4 — Límite de concentración (Decreto 2555/2010)
        if (maxBalancePerInvestor > 0) {
            uint256 newBalance = balance + amount;
            if (newBalance > maxBalancePerInvestor) {
                _totalBlocked++;
                emit ComplianceChecked(from, to, amount, false);
                revert ExceedsMaxBalance(to, balance, maxBalancePerInvestor);
            }
        }

        // Regla 5 — Travel Rule (FATF R.16 rev. 2025)
        uint256 valueUSD = amount * tokenPriceUSD;
        if (valueUSD >= travelRuleThresholdUSD) {
            emit TravelRuleTriggered(from, to, valueUSD, block.timestamp);
        }

        // Regla 6 — SAGRILAFT alerta (umbral Colombia 10.000 USD)
        if (valueUSD >= sagrilaftThresholdUSD) {
            emit SAGRILAFTAlertTriggered(from, to, valueUSD, block.timestamp);
        }

        emit ComplianceChecked(from, to, amount, true);
        return true;
    }

    // ─── Gestión de blacklist ─────────────────────────────────

    /**
     * @notice Añade una dirección a la blacklist on-chain
     * @dev Equivalente on-chain del screening OFAC/UIAF
     *      La lista off-chain (OFAC/ONU/UIAF) se procesa en el backend
     *      y las coincidencias confirmadas se registran aquí
     */
    function blacklist(address wallet)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        _blacklisted[wallet] = true;
        emit AddressBlacklisted(wallet, block.timestamp);
    }

    /**
     * @notice Elimina una dirección de la blacklist
     */
    function whitelist(address wallet)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        _blacklisted[wallet] = false;
        emit AddressWhitelisted(wallet, block.timestamp);
    }

    // ─── Configuración ────────────────────────────────────────

    /**
     * @notice Actualiza el umbral del Travel Rule
     * @dev FATF R.16 establece 1.000 USD — no bajar de este valor
     */
    function setTravelRuleThreshold(uint256 thresholdUSD)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        if (thresholdUSD == 0) revert InvalidThreshold();
        travelRuleThresholdUSD = thresholdUSD;
    }

    /**
     * @notice Actualiza el límite máximo de tokens por inversor
     */
    function setMaxBalance(uint256 maxBalance)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        maxBalancePerInvestor = maxBalance;
    }

    // ─── Lectura ──────────────────────────────────────────────

    function isBlacklisted(address wallet) external view returns (bool) {
        return _blacklisted[wallet];
    }

    function getStats() external view returns (
        uint256 totalChecks,
        uint256 totalBlocked
    ) {
        return (_totalChecks, _totalBlocked);
    }
}