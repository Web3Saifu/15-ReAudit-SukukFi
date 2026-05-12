// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC7540Operator} from "./interfaces/IERC7540.sol";
import {IERC7575, IERC7575ShareExtended} from "./interfaces/IERC7575.sol";

import {IERC7575Errors} from "./interfaces/IERC7575Errors.sol";
import {IVaultMetrics} from "./interfaces/IVaultMetrics.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
// Interface for WERC7575 share tokens with restricted balance functionality

interface IWERC7575ShareToken {
    function rBalanceOf(address account) external view returns (uint256);
}

import {DecimalConstants} from "./DecimalConstants.sol";
import {ERC7575VaultUpgradeable} from "./ERC7575VaultUpgradeable.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

// Forward declaration to avoid circular dependency
interface IERC7575Vault {
    function getClaimableSharesAndNormalizedAssets() external view returns (uint256 claimableShares, uint256 normalizedAssets);
}

/**
 * @title ShareTokenUpgradeable
 * @dev FULLY COMPLIANT ERC7575Share + ERC7540Operator + ERC20 token for multi-asset vault systems
 *
 * ERC7575 COMPLIANCE VERIFICATION:
 * IERC7575ShareExtended Interface (https://eips.ethereum.org/EIPS/eip-7575)
 *    - vault(address asset) → returns vault address for asset
 *    - getRegisteredAssets() → returns all registered assets
 *    - getTotalNormalizedAssets() → aggregates across all vaults
 *    - VaultUpdate event emission on registration/unregistration
 *    - Multi-asset registry with asset→vault mapping
 *
 * ERC7540 OPERATOR COMPLIANCE VERIFICATION:
 * IERC7540Operator Interface (https://eips.ethereum.org/EIPS/eip-7540)
 *    - setOperator(operator, approved) → centralized operator management
 *    - isOperator(controller, operator) → unified operator checks
 *    - OperatorSet event emission on operator changes
 *    - CENTRALIZED: One operator setting works across ALL vaults
 *
 * ARCHITECTURE FEATURES:
 * - Shared across multiple ERC7575VaultUpgradeable contracts (one per asset)
 * - Decimal normalization for cross-asset aggregation (18-decimal standard)
 * - Vault-only minting/burning with proper authorization controls
 * - Registry management for asset-to-vault relationships
 * - CENTRALIZED operator management for all vaults (better UX)
 * - CENTRALIZED investment manager control with automatic propagation to all vaults
 * - CENTRALIZED investment ShareToken configuration for unified investment strategy
 * - ERC165 interface detection support
 *
 * SECURITY:
 * - Only registered vaults can mint/burn tokens (onlyVaults modifier)
 * - Safe vault registration/unregistration with outstanding share checks
 * - Integer overflow protection with Math.mulDiv in aggregation
 * - Centralized operator validation prevents fragmented permissions
 * - Upgradeable with storage slots pattern for safe upgrades
 */
contract ShareTokenUpgradeable is Initializable, ERC20Upgradeable, Ownable2StepUpgradeable, IERC7575ShareExtended, IERC7540Operator, IERC165, IERC7575Errors {
    using EnumerableMap for EnumerableMap.AddressToAddressMap;
    // Storage slot for ShareToken-specific data

    // Note: Common errors are now inherited from IERC7575Errors interface

    bytes32 private constant SHARE_TOKEN_STORAGE_SLOT = keccak256("erc7575.sharetoken.storage");
    // Security constants
    uint256 private constant VIRTUAL_SHARES = 1e6; // Virtual shares for inflation protection
    uint256 private constant VIRTUAL_ASSETS = 1e6; // Virtual assets for inflation protection
    uint256 private constant MAX_VAULTS_PER_SHARE_TOKEN = 10; // DoS mitigation: prevents unbounded loop in aggregation

    // Note: OperatorSet event is defined in IERC7540Operator interface

    struct ShareTokenStorage {
        // EnumerableMap from asset to vault address (replaces both vaults mapping and registeredAssets array)
        EnumerableMap.AddressToAddressMap assetToVault;
        // Reverse mapping from vault to asset for quick lookup
        mapping(address vault => address asset) vaultToAsset;
        // ERC7540 Operator mappings - centralized for all vaults
        mapping(address controller => mapping(address operator => bool approved)) operators;
        // Investment configuration - centralized at ShareToken level
        address investmentShareToken; // The ShareToken used for investments
        address investmentManager; // Centralized investment manager for all vaults
    }

    /**
     * @dev Returns the ShareToken storage struct
     */
    function _getShareTokenStorage() private pure returns (ShareTokenStorage storage $) {
        bytes32 slot = SHARE_TOKEN_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract
     * @param name Token name
     * @param symbol Token symbol
     * @param owner Initial owner address
     */
    function initialize(string memory name, string memory symbol, address owner) public initializer {
        __ERC20_init(name, symbol);
        __Ownable_init(owner);

        // Enforce 18 decimals for consistency with ERC7575 standard
        if (decimals() != DecimalConstants.SHARE_TOKEN_DECIMALS) {
            revert WrongDecimals();
        }
    }

    // Modifier to restrict minting/burning to registered vaults
    modifier onlyVaults() {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.vaultToAsset[msg.sender] == address(0)) revert Unauthorized();
        _;
    }

    /**
     * @dev Returns the vault address for a specific asset
     *
     * ERC7575 SPECIFICATION (IERC7575ShareExtended interface):
     * "Returns the vault address for a specific asset.
     * Allows share tokens to point back to their vaults."
     *
     * @param asset The asset token address
     * @return vaultAddress The vault address that handles this asset
     */
    function vault(address asset) external view override returns (address vaultAddress) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        (, vaultAddress) = $.assetToVault.tryGet(asset);
    }

    /**
     * @dev Registers a new vault for an asset in the multi-asset system (ERC7575 compliant)
     *
     * Establishes a one-to-one relationship between an asset and a vault. All users
     * depositing/redeeming that asset will use this vault. Automatically configures
     * the new vault with existing investment settings for seamless integration.
     *
     * MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens." (ERC7575 specification)
     *
     * AUTOMATIC CONFIGURATION:
     * When a vault is registered, it automatically inherits:
     * - Investment ShareToken configuration (if already set)
     * - Investment manager (if already configured)
     * - Appropriate allowances for investment operations
     *
     * This ensures newly registered vaults work immediately without separate setup.
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7575: Multi-asset vault standard
     * - One-to-one asset-to-vault mapping enforced
     * - DoS mitigation: Maximum 10 vaults per share token
     * - VaultUpdate event emission
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Validates vault configuration before registration
     *
     * VALIDATION:
     * - Asset and vault addresses must not be zero
     * - Asset must not already be registered
     * - Vault's asset() must match the asset parameter
     * - Vault's share() must match this ShareToken address
     * - Total vaults must not exceed MAX_VAULTS_PER_SHARE_TOKEN (10)
     *
     * @param asset The asset token address to register
     * @param vaultAddress The vault contract address for this asset
     *
     * @custom:throws ZeroAddress If asset or vault address is zero
     * @custom:throws AssetMismatch If vault.asset() != provided asset
     * @custom:throws VaultShareMismatch If vault.share() != this ShareToken
     * @custom:throws AssetAlreadyRegistered If asset is already registered
     * @custom:throws MaxVaultsExceeded If maximum vault limit (10) is reached
     *
     * @custom:event VaultUpdate(asset, vaultAddress)
     */
    function registerVault(address asset, address vaultAddress) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();

        // Validate that vault's asset matches the provided asset parameter
        if (IERC7575(vaultAddress).asset() != asset) revert AssetMismatch();

        // Validate that vault's share token matches this ShareToken
        if (IERC7575(vaultAddress).share() != address(this)) {
            revert VaultShareMismatch();
        }

        ShareTokenStorage storage $ = _getShareTokenStorage();

        // DoS mitigation: Enforce maximum vaults per share token to prevent unbounded loop in getCirculatingSupplyAndAssets
        if ($.assetToVault.length() >= MAX_VAULTS_PER_SHARE_TOKEN) {
            revert MaxVaultsExceeded();
        }
        

        // Register new vault - set() returns true if newly added, false if already existed
        if (!$.assetToVault.set(asset, vaultAddress)) {
            revert AssetAlreadyRegistered();
        }
        $.vaultToAsset[vaultAddress] = asset;

        // If investment ShareToken is already configured, set up investment for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentShareToken = $.investmentShareToken;
        if (investmentShareToken != address(0)) {
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken);
        }

        // If investment manager is already configured, set it for the new vault
        // Only configure if the vault address is a deployed contract
        address investmentManager = $.investmentManager;
        if (investmentManager != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(investmentManager);
        }

        emit VaultUpdate(asset, vaultAddress);
    }

    /**
     * @dev Unregisters a vault and removes it from the multi-asset system (ERC7575 compliant)
     *
     * Removes a vault from the asset-to-vault registry. This is a permanent operation
     * that can only be performed when the vault has zero pending requests and no remaining
     * assets, ensuring no user funds are at risk.
     *
     * PREREQUISITES FOR UNREGISTRATION:
     * The vault must meet ALL of these conditions:
     * 1. Vault must be inactive (isActive = false)
     * 2. No pending deposit requests (totalPendingDepositAssets = 0)
     * 3. No claimable redemptions (totalClaimableRedeemAssets = 0)
     * 4. No ERC7887 pending/claimable cancelations (totalCancelDepositAssets = 0)
     * 5. No active deposit requesters (activeDepositRequestersCount = 0)
     * 6. No active redeem requesters (activeRedeemRequestersCount = 0)
     * 7. No asset tokens remaining in vault balance
     *
     * SAFETY GUARANTEES:
     * - Comprehensive multi-step validation prevents accidental unregistration
     * - Checks both request state and physical asset balance
     * - Catches investment vaults and edge cases
     * - Atomic operation: all validations or complete rollback
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7575: Multi-asset vault standard
     * - Safe unregistration without user fund loss
     * - VaultUpdate event emission with zero address
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Owner responsibility to pause vault before unregistration
     *
     * @param asset The asset token address to unregister
     *
     * @custom:throws ZeroAddress If asset address is zero
     * @custom:throws AssetNotRegistered If asset is not currently registered
     * @custom:throws CannotUnregisterActiveVault If vault is still active
     * @custom:throws CannotUnregisterVaultPendingDeposits If pending deposits exist
     * @custom:throws CannotUnregisterVaultClaimableRedemptions If claimable redemptions exist
     * @custom:throws CannotUnregisterVaultAssetBalance If ERC7887 cancelations or assets remain
     * @custom:throws CannotUnregisterVaultActiveDepositRequesters If active deposit requesters exist
     * @custom:throws CannotUnregisterVaultActiveRedeemRequesters If active redeem requesters exist
     *
     * @custom:event VaultUpdate(asset, address(0))
     */
    function unregisterVault(address asset) external onlyOwner {//👉 Removes a vault from the system
        if (asset == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        (bool exists, address vaultAddress) = $.assetToVault.tryGet(asset);//Is this asset registered?,,Get its vault
        if (!exists) revert AssetNotRegistered();

        // COMPREHENSIVE SAFETY CHECK: Ensure vault has no user funds at risk
        // This covers pending deposits, claimable redemptions, ERC7887 cancelations, and any remaining assets

        // 1. Check vault metrics for pending requests, active users, and ERC7887 cancelation assets
        try IVaultMetrics(vaultAddress).getVaultMetrics() returns (IVaultMetrics.VaultMetrics memory metrics) {//“Is this vault completely safe to remove without harming users?”
            if (metrics.isActive) revert CannotUnregisterActiveVault();//Vault is still operating → cannot remove
            if (metrics.totalPendingDepositAssets != 0) {//👉 users have money waiting to be processed
                revert CannotUnregisterVaultPendingDeposits();
            }
            if (metrics.totalClaimableRedeemAssets != 0) {//👉 users waiting to withdraw funds
                revert CannotUnregisterVaultClaimableRedemptions();
            }
            if (metrics.totalCancelDepositAssets != 0) {//👉 some assets still in cancel flow
                revert CannotUnregisterVaultAssetBalance();
            }
            if (metrics.activeDepositRequestersCount != 0) {
                revert CannotUnregisterVaultActiveDepositRequesters();
            }
            if (metrics.activeRedeemRequestersCount != 0) {
                revert CannotUnregisterVaultActiveRedeemRequesters();
            }
        } catch {
            // If we can't get vault metrics, we can't safely verify no pending requests
            revert CannotUnregisterActiveVault();
        }
        // 2. Final safety: Check raw asset balance in vault contract
        // This catches any remaining assets including investments and edge cases
        // If this happens, there is either a bug in the vault
        // or assets were sent to the vault without directly
        if (IERC20(asset).balanceOf(vaultAddress) != 0) {
            revert CannotUnregisterVaultAssetBalance();//“Check if the vault still holds any real ERC20 tokens of this asset.”
        }

        // Remove vault registration (automatically removes from enumerable collection)
        $.assetToVault.remove(asset);//“This asset no longer has any vault in system”
        delete $.vaultToAsset[vaultAddress];

        emit VaultUpdate(asset, address(0));
    }

    /**
     * @dev Returns whether an address is a registered vault.
     */
    /**
     * @dev Checks if an address is a registered vault
     * @param vaultAddress The address to check
     * @return True if the address is a registered vault
     */
    function isVault(address vaultAddress) external view returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.vaultToAsset[vaultAddress] != address(0);
    }

    /**
     * @dev Returns all registered assets in the multi-asset system
     *
     * ERC7575 SPECIFICATION (IERC7575ShareExtended interface):
     * "Returns all registered assets in the multi-asset system."
     *
     * MULTI-ASSET ARCHITECTURE:
     * "Multi-Asset Vaults share a single `share` token with multiple entry points
     * denominated in different `asset` tokens."
     *
     * @return Array of all asset addresses that have registered vaults
     */
    function getRegisteredAssets() external view returns (address[] memory) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.assetToVault.keys();
    }

    /**
     * @dev Returns both circulating supply and normalized assets in a single call
     *
     * Circulating supply excludes shares held by vaults for redemption claims.
     * Total normalized assets excludes assets reserved for redemption claims.
     * Both values exclude the same economic scope for consistent conversion ratios.
     *
     * @return circulatingSupply Total supply minus shares held by vaults for redemption claims
     * @return totalNormalizedAssets Total normalized assets across all vaults (18 decimals)
     */
    function getCirculatingSupplyAndAssets() external view returns (uint256 circulatingSupply, uint256 totalNormalizedAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        uint256 totalClaimableShares = 0;
        uint256 length = $.assetToVault.length();

        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Get both claimable shares and normalized assets in a single call for gas efficiency
            (uint256 vaultClaimableShares, uint256 vaultNormalizedAssets) = IERC7575Vault(vaultAddress).getClaimableSharesAndNormalizedAssets();
            totalClaimableShares += vaultClaimableShares;
            totalNormalizedAssets += vaultNormalizedAssets;
        }

        // Add invested assets from the investment ShareToken (if configured)
        totalNormalizedAssets += _calculateInvestmentAssets();

        // Get total supply
        uint256 supply = totalSupply();
        // Calculate circulating supply: total supply minus vault-held shares for redemption claims
        circulatingSupply = totalClaimableShares > supply ? 0 : supply - totalClaimableShares;
    }

    /**
     * @dev Mint shares to an account. Only callable by authorized vaults.
     */
    /**
     * @dev Mints shares to an account (only registered vaults)
     * @param account The account to mint shares to
     * @param amount The amount of shares to mint
     */
    function mint(address account, uint256 amount) external onlyVaults {
        _mint(account, amount);
    }

    /**
     * @dev Burn shares from an account. Only callable by authorized vaults.
     */
    /**
     * @dev Burns shares from an account (only registered vaults)
     * @param account The account to burn shares from
     * @param amount The amount of shares to burn
     */
    function burn(address account, uint256 amount) external onlyVaults {
        _burn(account, amount);
    }

    /**
     * @dev Spends allowance for an owner (vault-only operation)
     * @param owner The owner address whose shares are being spent
     * @param spender The spender address spending the allowance
     * @param amount The amount of shares to spend from allowance
     */
    function spendAllowance(address owner, address spender, uint256 amount) external onlyVaults {
        _spendAllowance(owner, spender, amount);
    }

    // ========== IERC7540Operator Implementation ==========

    /**
     * @dev Sets or unsets an operator for the caller (centralized for all vaults)
     *
     * ERC7540 SPECIFICATION:
     * "Grants or revokes permissions for `operator` to manage Requests on behalf of the `msg.sender`.
     * - MUST set the operator status to the `approved` value.
     * - MUST log the `OperatorSet` event.
     * - MUST return True."
     *
     * CENTRALIZED ARCHITECTURE:
     * Unlike vault-level operators, this implementation provides unified operator
     * management across ALL ERC7575 vaults that use this ShareToken.
     *
     * @param operator Address of the operator
     * @param approved True to approve, false to revoke
     * @return True if successful
     */
    /**
     * @dev Sets or revokes operator approval for the caller (ERC7540 compliant)
     *
     * Allows users to centrally approve operators who can manage async requests
     * across ALL vaults in the multi-asset system. Single operator approval works
     * for deposits, redeems, and cancelations in all vaults sharing this ShareToken.
     *
     * CENTRALIZED OPERATOR SYSTEM:
     * One operator approval provides authorization across:
     * - All ERC7575 vaults (deposits/redeems)
     * - All ERC7887 cancelations
     * - All asset classes in the multi-asset system
     *
     * SPECIFICATION COMPLIANCE:
     * - ERC7540: Asynchronous Tokenized Vault Standard
     * - Centralized operator delegation
     * - OperatorSet event emission 
     *
     * OPERATOR PERMISSIONS:
     * 
     * Approved operators can:
     * - Call requestDeposit on behalf of owner
     * - Call requestRedeem on behalf of owner
     * - Call cancelDepositRequest on behalf of controller
     * - Call cancelRedeemRequest on behalf of controller
     * - Call claim functions (deposit/redeem/cancelation) on behalf of controller
     * - Works across all vaults in the system
     *
     * @param operator Address to approve or revoke as an operator
     * @param approved True to grant operator permission, false to revoke
     *
     * @return Always returns true to indicate operation succeeded
     *
     * @custom:throws CannotSetSelfAsOperator If operator == msg.sender
     * @custom:event OperatorSet(msg.sender, operator, approved)
     */
    function setOperator(address operator, bool approved) external virtual returns (bool) {
        if (msg.sender == operator) revert CannotSetSelfAsOperator();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        $.operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }

    /**
     * @dev Checks if an operator is approved for a controller (centralized for all vaults)
     *
     * ERC7540 SPECIFICATION:
     * "Returns `true` if the `operator` is approved as an operator for a `controller`."
     *
     * CENTRALIZED ARCHITECTURE:
     * This single function serves ALL ERC7575 vaults, providing consistent
     * operator permissions across the entire multi-asset system.
     *
     * @param controller Address of the controller
     * @param operator Address of the operator
     * @return True if operator is approved
     */
    function isOperator(address controller, address operator) external view virtual returns (bool) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.operators[controller][operator];
    }

    /**
     * @dev Sets or revokes operator approval for a specific controller (vault-delegation)
     *
     * Internal delegation function allowing vaults to set operators on behalf of users
     * while preserving the original user context. This enables vaults to delegate
     * operator setup to their own logic if needed.
     *
     * VAULT DELEGATION:
     * - Only callable by registered vaults
     * - Preserves original controller identity
     * - Centralized operator tracking
     *
     * @param controller Address of the controller (the user)
     * @param operator Address to approve or revoke as operator
     * @param approved True to grant operator permission, false to revoke
     *
     * @custom:throws CannotSetSelfAsOperator If operator == controller
     */
    function setOperatorFor(address controller, address operator, bool approved) external onlyVaults {
        if (controller == operator) revert CannotSetSelfAsOperator();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        $.operators[controller][operator] = approved;
        emit OperatorSet(controller, operator, approved);
    }

    // ========== Investment Configuration Management ==========

    /**
     * @dev Internal helper function to configure investment settings for a single vault
     * @param asset The asset address
     * @param vaultAddress The vault address to configure
     * @param investmentShareToken The investment ShareToken address
     */
    function _configureVaultInvestmentSettings(address asset, address vaultAddress, address investmentShareToken) internal {
        // Find the corresponding investment vault for this asset
        address investmentVaultAddress = IERC7575ShareExtended(investmentShareToken).vault(asset);

        // Configure investment vault if there's a matching one for this asset
        if (investmentVaultAddress != address(0)) {
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentVault(IERC7575(investmentVaultAddress));

            // Grant unlimited allowance to the vault on the investment ShareToken
            IERC20(investmentShareToken).approve(vaultAddress, type(uint256).max);
        }
    }

    /**
     * @dev Sets the investment ShareToken address and configures all vault investment mappings (only owner)
     *
     * This function:
     * 1. Sets the investment ShareToken for the multi-asset system
     * 2. Iterates through all registered assets
     * 3. For each asset, finds the matching investment vault from the investment ShareToken
     * 4. Configures each vault with its corresponding investment vault
     *
     * ARCHITECTURE:
     * - All investments will be made in the name of this ShareToken
     * - Each vault will have its counterpart investment vault (same asset)
     * - Enables centralized investment management across the multi-asset system
     *
     * @param investmentShareToken_ The address of the investment ShareToken
     */
    function setInvestmentShareToken(address investmentShareToken_) external onlyOwner {
        if (investmentShareToken_ == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();
        if ($.investmentShareToken != address(0)) {
            revert InvestmentShareTokenAlreadySet();
        }

        // Store the investment ShareToken address
        $.investmentShareToken = investmentShareToken_;

        // Iterate through all registered assets and configure investment vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (address asset, address vaultAddress) = $.assetToVault.at(i);
            _configureVaultInvestmentSettings(asset, vaultAddress, investmentShareToken_);
        }

        emit InvestmentShareTokenSet(investmentShareToken_);
    }

    /**
     * @dev Returns the current investment ShareToken address
     *
     * @return The address of the investment ShareToken, or zero address if not set
     */
    function getInvestmentShareToken() external view returns (address) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.investmentShareToken;
    }

    /**
     * @dev Helper function to calculate total investment assets (balanceOf + rBalanceOf)
     * @return totalInvestmentAssets Total invested assets including reserved balance
     */
    function _calculateInvestmentAssets() internal view returns (uint256 totalInvestmentAssets) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        address investmentShareToken = $.investmentShareToken;

        if (investmentShareToken == address(0)) {
            return 0;
        }

        // Get our balance of investment ShareToken (already normalized to 18 decimals)
        totalInvestmentAssets = IERC20(investmentShareToken).balanceOf(address(this));

        // Add rBalanceOf (reserved balance) if the investment share token supports it
        try IWERC7575ShareToken(investmentShareToken).rBalanceOf(address(this)) returns (uint256 rShares) {
            totalInvestmentAssets += rShares;
        } catch {
            // If rBalanceOf is not supported, continue with regular balance only
        }
    }

    /**
     * @dev Gets the total value of invested assets (normalized to 18 decimals)
     * @return Total value of assets invested through the investment ShareToken
     */
    function getInvestedAssets() external view returns (uint256) {
        return _calculateInvestmentAssets();
    }

    /**
     * @dev Sets the investment manager for all vaults (centralized management)
     *
     * Establishes centralized investment management by designating a single manager
     * responsible for fulfilling all deposit/redeem requests across all vaults in the
     * multi-asset system. The manager is automatically propagated to all registered vaults.
     *
     * CENTRALIZED INVESTMENT ARCHITECTURE:
     * - Single investment manager for ALL vaults
     * - Automatic propagation to existing vaults
     * - Automatic assignment to new vaults during registration
     * - Unified investment strategy across asset classes
     *
     * INVESTMENT MANAGER RESPONSIBILITIES:
     * - Call fulfillDeposit/fulfillDeposits to convert pending assets to shares
     * - Call fulfillRedeem to convert pending shares to assets
     * - Call fulfillCancelDepositRequest(s) for deposit cancelations
     * - Call fulfillCancelRedeemRequest(s) for redeem cancelations
     * - Manage investments through the investment vault
     * - Monitor vault metrics and manage liquidity
     *
     * ACCESS CONTROL:
     * - Only callable by share token owner
     * - Not restricted once set (can be changed by owner)
     *
     * @param newInvestmentManager The address of the new investment manager
     *
     * @custom:throws ZeroAddress If newInvestmentManager is zero address
     */
    function setInvestmentManager(address newInvestmentManager) external onlyOwner {
        if (newInvestmentManager == address(0)) revert ZeroAddress();
        ShareTokenStorage storage $ = _getShareTokenStorage();

        // Store the investment manager centrally
        $.investmentManager = newInvestmentManager;

        // Propagate to all registered vaults
        uint256 length = $.assetToVault.length();
        for (uint256 i = 0; i < length; i++) {
            (, address vaultAddress) = $.assetToVault.at(i);

            // Call setInvestmentManager on each vault
            ERC7575VaultUpgradeable(vaultAddress).setInvestmentManager(newInvestmentManager);
        }

        emit InvestmentManagerSet(newInvestmentManager);
    }

    /**
     * @dev Returns the current investment manager address
     * @return The address of the centralized investment manager
     */
    function getInvestmentManager() external view returns (address) {
        ShareTokenStorage storage $ = _getShareTokenStorage();
        return $.investmentManager;
    }

    /**
     *  OPTIMIZED CONVERSION: Normalized assets to shares with mathematical consistency
     *
     * - Assets: excludes reserved redemption assets
     * - Shares: excludes vault-held shares for redemption claims
     * Result: Both numerator and denominator represent the same economic scope
     *
     * VIRTUAL ASSETS/SHARES:
     * Added for inflation protection as per ERC4626 best practices
     *
     * @param normalizedAssets Amount of normalized assets (18 decimals)
     * @param rounding Rounding mode for the conversion
     * @return shares Amount of shares equivalent to the normalized assets
     */
    function convertNormalizedAssetsToShares(uint256 normalizedAssets, Math.Rounding rounding) external view returns (uint256 shares) {//👉 Converts assets → shares
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();//circulatingSupply shares actively owned by users,, total value of vault

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;//circulatingSupply = 1000 + 1,000,000
        totalNormalizedAssets += VIRTUAL_ASSETS;//totalAssets = 2000 + 1,000,000

        // shares = normalizedAssets * circulatingSupply / totalNormalizedAssets
        shares = Math.mulDiv(normalizedAssets, circulatingSupply, totalNormalizedAssets, rounding);
    }

    /**
     *  OPTIMIZED CONVERSION: Shares to normalized assets with mathematical consistency
     *
     * MATHEMATICAL CONSISTENCY:
     * This function uses the same circulating supply approach as convertNormalizedAssetsToShares
     * to ensure consistent conversion ratios in both directions during ERC7540 async operations.
     *
     * See convertNormalizedAssetsToShares documentation for detailed explanation of the
     * mathematical consistency fix.
     *
     * @param shares Amount of shares to convert
     * @param rounding Rounding mode for the conversion
     * @return normalizedAssets Amount of normalized assets (18 decimals) equivalent to the shares
     */
    function convertSharesToNormalizedAssets(uint256 shares, Math.Rounding rounding) external view returns (uint256 normalizedAssets) {
        // Get both values in a single call
        (uint256 circulatingSupply, uint256 totalNormalizedAssets) = this.getCirculatingSupplyAndAssets();

        // Add virtual amounts for inflation protection
        circulatingSupply += VIRTUAL_SHARES;
        totalNormalizedAssets += VIRTUAL_ASSETS;

        // normalizedAssets = shares * totalNormalizedAssets / circulatingSupply
        normalizedAssets = Math.mulDiv(shares, totalNormalizedAssets, circulatingSupply, rounding);
    }

    /**
     * @dev Transfers shares from owner to vault without requiring allowance (vault-only operation)
     * This function is essential for ERC7540 operator functionality, allowing operators to
     * submit redemption requests on behalf of users without requiring pre-approval.
     *
     * @param from The owner address to transfer shares from
     * @param to The recipient address (typically the vault)
     * @param amount The amount of shares to transfer
     * @return success True if transfer successful
     */
    function vaultTransferFrom(address from, address to, uint256 amount) external onlyVaults returns (bool success) {
        if (from == address(0)) {
            revert IERC20Errors.ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert IERC20Errors.ERC20InvalidReceiver(address(0));
        }

        // Direct transfer without checking allowance since this is vault-only
        _transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Event emitted when the investment ShareToken is updated
     */
    event InvestmentShareTokenSet(address indexed investmentShareToken);

    /**
     * @dev Event emitted when the investment manager is updated
     */
    event InvestmentManagerSet(address indexed investmentManager);

    // ========== Upgrade Functions ==========

    /**
     * @dev Upgrade the implementation of the proxy (only owner)
     * @param newImplementation Address of the new implementation contract
     */
    function upgradeTo(address newImplementation) external onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, "");
    }

    /**
     * @dev Upgrade the implementation and call a function (only owner)
     * @param newImplementation Address of the new implementation contract
     * @param data Calldata to execute on the new implementation
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyOwner {
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }

    // ========== ERC165 Support ==========

    /**
     * @dev Returns true if this contract implements the interface (ERC165)
     * @param interfaceId The interface identifier
     * @return True if interface is supported
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC7575ShareExtended).interfaceId || interfaceId == type(IERC7540Operator).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
