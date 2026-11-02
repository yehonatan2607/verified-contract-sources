// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// ====================================================================
// |                       Imports                                  |
// ====================================================================

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import {
    AccessControlUpgradeable,
    AccessControlEnumerableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IPermit2, ISignatureTransfer } from "./interfaces/IPermit2.sol";
import { ISynthetixDepositContract } from "./interfaces/ISynthetixDepositContract.sol";
import { ReasonCodes } from "./libraries/ReasonCodes.sol";
import { AggregatorV3Interface } from "./interfaces/AggregatorV3Interface.sol";
import { CowOrder } from "./libraries/CowProtocol.sol";

/**
 * @title Synthetix Deposit Contract
 * @author 0xMithrandir
 * @notice This contract is the secure custody layer for the Synthetix perps exchange.
 * It handles all user deposits and manages a multi-stage, role-based withdrawal process.
 * @dev UUPS Upgradeable. All administrative actions MUST be controlled by a Timelock.
 */
contract SynthetixDepositContract is
    ISynthetixDepositContract,
    IERC1271,
    Initializable,
    UUPSUpgradeable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;
    using CowOrder for CowOrder.Data;

    // ====================================================================
    // |                      Constants and Roles                       |
    // ====================================================================

    /// @notice Address of the Permit2 contract for gasless approvals
    address public constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// @notice CoW Protocol EIP-712 domain separator (Ethereum Mainnet)
    /// @dev This is the deterministic domain separator for GPv2Settlement on Ethereum mainnet.
    ///      Extracted from the `domainSeparator` view function at
    ///      https://etherscan.io/address/0x9008d19f58aabd9ed0d60971565aa8510560ab41#readContract#F2
    bytes32 private constant COW_DOMAIN_SEPARATOR = 0xc078f884a2676e1345748b1feace7b0abee5d00ecadb6e574dcdd109a63e8943;

    // Sepolia domain separator
    // bytes32 private constant COW_DOMAIN_SEPARATOR =
    // 0xdaee378bd0eb30ddf479272accf91761e697bc00e067a268f95f1d2732ed230b;

    /// @notice CoW Protocol VaultRelayer address (cross-chain deterministic)
    /// @dev The address from which CoW Protocol will attempt to retrieve tokens for order
    ///      settlement. This address is consistent across all chains where CoW Protocol is deployed.
    ///      This was extracted from the `vaultRelayer` view function at
    ///      https://etherscan.io/address/0x9008d19f58aabd9ed0d60971565aa8510560ab41#readContract#F7
    address private constant COW_VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;

    /// @notice USDT token address on Ethereum mainnet (target settlement asset)
    address public constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    // Sepolia USDT address
    // address public constant USDT = 0x58Eb19eF91e8A6327FEd391b51aE1887b833cc91;

    /// @notice USDT token decimals on Ethereum mainnet
    uint8 private constant USDT_DECIMALS = 6;

    /// @notice Role for relayers who approve/reject withdrawal requests
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Role for watchers who validate approved withdrawals
    bytes32 public constant WATCHER_ROLE = keccak256("WATCHER_ROLE");

    /// @notice Role for tellers who execute disbursements
    bytes32 public constant TELLER_ROLE = keccak256("TELLER_ROLE");

    /// @notice Role for guardians who can pause operations and resolve disputes
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /**
     * @dev The OWNER_ROLE (also referred to as TIMELOCK_ADMIN_ROLE in spec) is the only role that can execute sensitive
     * changes.
     * It is intended to be held by a TimelockController contract to enforce a delay
     * on all critical administrative actions, mitigating governance attacks.
     */
    /// @notice Role for the timelock controller with highest privileges
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    /**
     * @dev The MANAGER_ROLE has similar authority to OWNER_ROLE but without timelock requirements.
     * Used for quick operational actions like revoking roles.
     */
    /// @notice Role for operational management without timelock
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    /// @notice Role for authorized traders who can sign CoW swap orders
    bytes32 public constant AUTHORIZED_TRADER_ROLE = keccak256("AUTHORIZED_TRADER_ROLE");

    /// @notice ERC-1271 magic value for valid signatures
    bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;

    /// @notice Fixed point scale (1e18)
    uint256 private constant WAD = 1e18;

    /// @notice Minimum ABI-encoded envelope length (bytes):
    /// 12 head words (12*32) + bytes length (32) + padded 65-byte sig (96) = 512
    uint256 private constant MIN_ENVELOPE_LENGTH = 512;

    /// @notice Basis points denominator
    uint256 private constant BPS_DENOMINATOR = 10_000;

    // ====================================================================
    // |                        State Variables                         |
    // ====================================================================

    mapping(address collateralToken => CollateralConfig) private _collateralConfigs;
    mapping(uint256 requestId => WithdrawalRequest) private _withdrawalRequests;
    mapping(address user => uint256) private _userActiveWithdrawalId;
    mapping(uint256 requestId => mapping(address watcher => bool voted)) private _watcherVotes;
    mapping(address collateralToken => uint256) private _totalDeposited;
    mapping(address user => mapping(address collateralToken => int256 balance)) private _userBalance;
    mapping(address guardian => mapping(address collateralToken => uint256 approvalLimit)) private
        _guardianApprovalLimits;

    uint256 private _withdrawalRequestCounter;
    /// @notice Number of watcher votes required to validate a withdrawal
    uint256 public watcherQuorum;
    /// @notice Time in seconds after which a withdrawal request expires
    uint256 public withdrawalExpiryTimeout;

    // Granular pause states
    /// @notice Whether all deposits are paused globally
    bool public depositsGloballyPaused;
    /// @notice Whether all withdrawals are paused globally
    bool public withdrawalsGloballyPaused;
    /// @notice Per-token deposit pause status
    mapping(address => bool) public tokenDepositsPaused;
    /// @notice Per-token withdrawal pause status
    mapping(address => bool) public tokenWithdrawalsPaused;

    /// @notice Allowed slippage (in basis points) on the CoW order relative to oracle price
    /// Example: 500 = 5% tolerance. If zero, price checks are effectively disabled.
    uint256 public slippageToleranceBps;

    struct PriceFeedConfig {
        address aggregator;
        uint48 staleTimeout;
    }

    /// @notice Mapping of token => Chainlink USD price feed configuration
    mapping(address token => PriceFeedConfig) private _priceFeedsUSD;

    /// @notice Maximum allowed age for oracle data in seconds. Acts as default when no per-token timeout is set.
    uint256 public maxOracleStaleTimeout;

    /// @notice Address of the SLP Vault contract authorized to pull USDT rewards
    address public slpVault;

    mapping(address user => uint256[] requestIds) private _userWithdrawalRequestIds;

    // ====================================================================
    // |                         Custom Errors                          |
    // ====================================================================

    error ZeroAddress();
    error ZeroAmount();
    error TokenNotSupported();
    error InvalidPermit();
    error ActiveWithdrawalExists();
    error InvalidInput();
    error InvalidStateForAction(uint256 id, Status currentStatus);
    error AlreadyFinalized(uint256 id);
    error NotYourRequest(uint256 id, address caller);
    error RequestDoesNotExist(uint256 id);
    error EthDepositsNotSupported();
    error DepositsGloballyPaused();
    error WithdrawalsGloballyPaused();
    error TokenDepositsPaused(address token);
    error TokenWithdrawalsPaused(address token);
    error InsufficientContractBalance(address token, uint256 requested, uint256 available);
    error UnauthorizedRole();
    error AmountBelowMinimum(address token, uint256 amount, uint256 minimum);
    error ExceedsGlobalMaximum(address token, uint256 newTotal, uint256 maximum);
    error ExceedsUserMaximum(address token, uint256 newBalance, uint256 maximum);
    error GuardianApprovalLimitExceeded(address token, uint256 amount, uint256 limit);
    error InputArrayLengthMismatch();
    error ContractPaused();
    error UnauthorizedSigner();
    error InvalidEnvelope();
    error InvalidTradeParams();
    error InvalidTradeSignature();
    error InvalidReceiver(address receiver);
    error PriceFeedNotSet(address token);
    error InvalidOracleAnswer();
    error OraclePriceStale(address feed, uint256 updatedAt);

    // ====================================================================
    // |                   Initializer & Constructor                    |
    // ====================================================================

    /// @notice Constructor that disables initializers
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract, setting up the Timelock as the sole administrator
     * @param _timelockAddress The address of the TimelockController that will govern this contract
     * @dev Sets up all role admins and default configurations
     */
    function initialize(address _timelockAddress) public initializer {
        __UUPSUpgradeable_init();
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();

        if (_timelockAddress == address(0)) revert ZeroAddress();

        // Grant OWNER_ROLE to the timelock address
        _grantRole(OWNER_ROLE, _timelockAddress);
        // Set OWNER_ROLE as the admin of itself and MANAGER_ROLE
        _setRoleAdmin(OWNER_ROLE, OWNER_ROLE);
        _setRoleAdmin(MANAGER_ROLE, OWNER_ROLE);
        // Set MANAGER_ROLE as the admin of operational roles
        _setRoleAdmin(RELAYER_ROLE, MANAGER_ROLE);
        _setRoleAdmin(WATCHER_ROLE, MANAGER_ROLE);
        _setRoleAdmin(TELLER_ROLE, MANAGER_ROLE);
        _setRoleAdmin(GUARDIAN_ROLE, MANAGER_ROLE);
        _setRoleAdmin(AUTHORIZED_TRADER_ROLE, MANAGER_ROLE);

        // Set default withdrawal expiry timeout to 5 minutes (300 seconds)
        withdrawalExpiryTimeout = 300;
        // Default slippage tolerance to 5% (500 bps)
        slippageToleranceBps = 500;
        // Default oracle staleness timeout to 1 day + 1 second (supports feeds with 1 day heartbeat)
        maxOracleStaleTimeout = 1 days + 1 seconds;
    }

    modifier whenNotPaused() {
        if (depositsGloballyPaused && withdrawalsGloballyPaused) {
            revert ContractPaused();
        }
        _;
    }

    // ====================================================================
    // |                       Read-Only Functions                      |
    // ====================================================================

    /// @inheritdoc ISynthetixDepositContract
    function isCollateralSupported(address _token) external view returns (bool) {
        return _collateralConfigs[_token].enabled;
    }

    /// @inheritdoc ISynthetixDepositContract
    function getCollateralConfig(address _token) external view returns (CollateralConfig memory) {
        return _collateralConfigs[_token];
    }

    /// @inheritdoc ISynthetixDepositContract
    function getTotalDeposited(address _token) external view returns (uint256) {
        return _totalDeposited[_token];
    }

    /// @inheritdoc ISynthetixDepositContract
    function priceFeedsUSD(address _token) public view override returns (address) {
        return _priceFeedsUSD[_token].aggregator;
    }

    /// @inheritdoc ISynthetixDepositContract
    function getUserBalance(address _user, address _token) external view returns (int256) {
        return _userBalance[_user][_token];
    }

    /// @inheritdoc ISynthetixDepositContract
    function getGuardianApprovalLimit(address _guardian, address _token) external view returns (uint256) {
        return _guardianApprovalLimits[_guardian][_token];
    }

    /// @inheritdoc ISynthetixDepositContract
    function getWithdrawalRequest(uint256 _id) external view returns (WithdrawalRequest memory) {
        return _withdrawalRequests[_id];
    }

    /// @inheritdoc ISynthetixDepositContract
    function getActiveWithdrawalId(address _user) external view returns (uint256) {
        return _userActiveWithdrawalId[_user];
    }

    /// @inheritdoc ISynthetixDepositContract
    function getWithdrawalRequestCounter() external view returns (uint256) {
        return _withdrawalRequestCounter;
    }

    /// @inheritdoc ISynthetixDepositContract
    function getUserWithdrawalRequestIds(address _user) external view returns (uint256[] memory) {
        return _userWithdrawalRequestIds[_user];
    }

    // NOTE: getAllWithdrawalRequests and getWithdrawalRequestsByUser have been moved to
    // SynthetixDepositContractLens to reduce contract size. Use the lens contract for batch queries.

    // ====================================================================
    // |                     User-Facing Functions                      |
    // ====================================================================

    /// @inheritdoc ISynthetixDepositContract
    function deposit(DepositEntry[] calldata _deposits) external nonReentrant {
        if (depositsGloballyPaused) revert DepositsGloballyPaused();

        for (uint256 i = 0; i < _deposits.length; ++i) {
            DepositEntry calldata item = _deposits[i];
            if (item.token == address(0)) revert ZeroAddress();
            if (item.beneficiary == address(0)) revert ZeroAddress();
            if (item.amount == 0) revert ZeroAmount();

            CollateralConfig memory config = _collateralConfigs[item.token];
            if (!config.enabled) revert TokenNotSupported();
            if (tokenDepositsPaused[item.token]) {
                revert TokenDepositsPaused(item.token);
            }

            // Check deposit limits
            if (item.amount < config.userMinimum) {
                revert AmountBelowMinimum(item.token, item.amount, config.userMinimum);
            }

            uint256 newTotalDeposited = _totalDeposited[item.token] + item.amount;
            if (newTotalDeposited > config.globalMaximum) {
                revert ExceedsGlobalMaximum(item.token, newTotalDeposited, config.globalMaximum);
            }

            address beneficiary = item.beneficiary;
            int256 newUserBalance = _userBalance[beneficiary][item.token] + int256(item.amount);
            if (newUserBalance > int256(config.userMaximum)) {
                revert ExceedsUserMaximum(item.token, uint256(newUserBalance), config.userMaximum);
            }

            // Update tracking
            _totalDeposited[item.token] = newTotalDeposited;
            _userBalance[beneficiary][item.token] = newUserBalance;

            IERC20 token = IERC20(item.token);

            if (item.permitDetails.signature.length > 0) {
                ISignatureTransfer.PermitTransferFrom calldata p = item.permitDetails.permit;
                if (p.permitted.token != item.token || p.permitted.amount < item.amount || p.deadline < block.timestamp)
                {
                    revert InvalidPermit();
                }

                ISignatureTransfer.SignatureTransferDetails memory transferDetails =
                    ISignatureTransfer.SignatureTransferDetails({ to: address(this), requestedAmount: item.amount });

                // Execute the permit transfer with validated details
                IPermit2(PERMIT2).permitTransferFrom(p, transferDetails, msg.sender, item.permitDetails.signature);
            } else {
                token.safeTransferFrom(msg.sender, address(this), item.amount);
            }
            emit AssetDeposited(msg.sender, beneficiary, item.token, item.amount, item.subAccountId);
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function requestWithdrawal(WithdrawalEntry[] calldata _withdrawals) external onlyRole(RELAYER_ROLE) {
        if (withdrawalsGloballyPaused) revert WithdrawalsGloballyPaused();
        if (_withdrawals.length == 0) revert InvalidInput();

        for (uint256 i = 0; i < _withdrawals.length; ++i) {
            WithdrawalEntry calldata entry = _withdrawals[i];

            // Validate tokens and amounts arrays have same length
            if (entry.tokens.length != entry.amounts.length) {
                revert InvalidInput();
            }
            if (entry.tokens.length == 0) revert InvalidInput();
            if (entry.beneficiary == address(0)) revert ZeroAddress();

            // Check if user already has an active withdrawal
            uint256 activeId = _userActiveWithdrawalId[entry.beneficiary];
            if (activeId != 0) {
                WithdrawalRequest storage activeReq = _withdrawalRequests[activeId];

                // If the active withdrawal has expired, automatically finalize it
                if (_isWithdrawalExpired(activeReq)) {
                    _finalizeRequest(activeId, Status.Expired, ReasonCodes.REASON_EXPIRED);
                } else {
                    // Only revert if the active withdrawal is NOT expired
                    revert ActiveWithdrawalExists();
                }
            }

            // Validate each token and amount
            for (uint256 j = 0; j < entry.tokens.length; ++j) {
                CollateralConfig storage config = _collateralConfigs[entry.tokens[j]];
                if (!config.enabled) {
                    revert TokenNotSupported();
                }
                if (entry.amounts[j] == 0) revert ZeroAmount();
                if (tokenWithdrawalsPaused[entry.tokens[j]]) {
                    revert TokenWithdrawalsPaused(entry.tokens[j]);
                }
                if (config.withdrawalMinimum > 0 && entry.amounts[j] < config.withdrawalMinimum) {
                    revert AmountBelowMinimum(entry.tokens[j], entry.amounts[j], config.withdrawalMinimum);
                }
                // Validate contract has sufficient balance
                uint256 contractBalance = IERC20(entry.tokens[j]).balanceOf(address(this));
                if (contractBalance < entry.amounts[j]) {
                    revert InsufficientContractBalance(entry.tokens[j], entry.amounts[j], contractBalance);
                }
            }

            // Create new withdrawal request
            uint256 newId;
            unchecked {
                newId = ++_withdrawalRequestCounter;
            }

            WithdrawalRequest storage newRequest = _withdrawalRequests[newId];
            newRequest.requestTime = uint32(block.timestamp);
            newRequest.user = entry.beneficiary;
            newRequest.status = Status.Requested;
            newRequest.reasonCode = ReasonCodes.REASON_NONE;
            newRequest.tokens = entry.tokens;
            newRequest.amounts = entry.amounts;

            _userActiveWithdrawalId[entry.beneficiary] = newId;
            _userWithdrawalRequestIds[entry.beneficiary].push(newId);

            emit WithdrawalRequested(newId, entry.beneficiary, entry.tokens, entry.amounts, block.timestamp);
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function cancelWithdrawal(uint256 _id) external whenNotPaused {
        WithdrawalRequest storage req = _withdrawalRequests[_id];
        if (req.user != msg.sender) revert NotYourRequest(_id, msg.sender);

        // Check if withdrawal is expired
        if (_isWithdrawalExpired(req)) {
            _finalizeRequest(_id, Status.Expired, ReasonCodes.REASON_EXPIRED);
            return;
        }

        Status currentStatus = req.status;
        if (currentStatus == Status.Validated || _isFinalStatus(currentStatus) || currentStatus == Status.Disputed) {
            revert InvalidStateForAction(_id, currentStatus);
        }

        _finalizeRequest(_id, Status.Cancelled, ReasonCodes.CANCELLED_BY_USER);
    }

    // ====================================================================
    // |             Role-Protected Functions (Withdrawal Lifecycle)            |
    // ====================================================================

    /// @inheritdoc ISynthetixDepositContract
    function rejectWithdrawals(
        uint256[] calldata _ids,
        uint256[] calldata _reasonCodes
    )
        external
        onlyRole(RELAYER_ROLE)
        whenNotPaused
    {
        if (_ids.length != _reasonCodes.length) {
            revert InputArrayLengthMismatch();
        }
        for (uint256 i = 0; i < _ids.length; ++i) {
            WithdrawalRequest storage req = _withdrawalRequests[_ids[i]];
            if (_isWithdrawalExpired(req)) {
                _finalizeRequest(_ids[i], Status.Expired, ReasonCodes.REASON_EXPIRED);
                continue;
            }
            if (req.status == Status.Requested) {
                _finalizeRequest(_ids[i], Status.Denied, _reasonCodes[i]);
            }
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function disputeWithdrawals(uint256[] calldata _ids, uint256[] calldata _reasonCodes) external whenNotPaused {
        if (!hasRole(RELAYER_ROLE, msg.sender) && !hasRole(WATCHER_ROLE, msg.sender)) {
            revert UnauthorizedRole();
        }
        if (_ids.length != _reasonCodes.length) {
            revert InputArrayLengthMismatch();
        }
        for (uint256 i = 0; i < _ids.length; ++i) {
            uint256 requestId = _ids[i];
            WithdrawalRequest storage req = _withdrawalRequests[requestId];
            if (req.user == address(0)) revert RequestDoesNotExist(requestId);

            if (_isWithdrawalExpired(req)) {
                _finalizeRequest(requestId, Status.Expired, ReasonCodes.REASON_EXPIRED);
                continue;
            }

            if (req.status == Status.Requested) {
                _updateStatus(requestId, Status.Requested, Status.Disputed, _reasonCodes[i]);
            }
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function castWatcherVotes(uint256[] calldata _requestIds) external onlyRole(WATCHER_ROLE) whenNotPaused {
        for (uint256 i = 0; i < _requestIds.length; ++i) {
            uint256 requestId = _requestIds[i];
            WithdrawalRequest storage req = _withdrawalRequests[requestId];

            if (req.user == address(0)) revert RequestDoesNotExist(requestId);

            if (_isWithdrawalExpired(req)) {
                _finalizeRequest(requestId, Status.Expired, ReasonCodes.REASON_EXPIRED);
                continue;
            }

            if (req.status == Status.Requested && !_watcherVotes[requestId][msg.sender]) {
                _watcherVotes[requestId][msg.sender] = true;
                req.watcherCount++;

                if (req.watcherCount >= watcherQuorum) {
                    _updateStatus(requestId, Status.Requested, Status.Validated, ReasonCodes.REASON_NONE);
                }
            }
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function disburseWithdrawals(uint256[] calldata _requestIds) external onlyRole(TELLER_ROLE) nonReentrant {
        if (withdrawalsGloballyPaused) revert WithdrawalsGloballyPaused();

        for (uint256 i = 0; i < _requestIds.length; ++i) {
            uint256 requestId = _requestIds[i];
            WithdrawalRequest storage req = _withdrawalRequests[requestId];

            if (req.status == Status.Validated && req.user != address(0)) {
                if (_isWithdrawalExpired(req)) {
                    _finalizeRequest(requestId, Status.Expired, ReasonCodes.REASON_EXPIRED);
                    continue;
                }

                address user = req.user;
                address[] memory tokens = req.tokens;
                uint256[] memory amounts = req.amounts;

                _finalizeRequest(requestId, Status.Disbursed, ReasonCodes.REASON_NONE);

                for (uint256 j = 0; j < tokens.length; ++j) {
                    if (tokenWithdrawalsPaused[tokens[j]]) {
                        revert TokenWithdrawalsPaused(tokens[j]);
                    }
                    if (amounts[j] > IERC20(tokens[j]).balanceOf(address(this))) {
                        revert InsufficientContractBalance(
                            tokens[j], amounts[j], IERC20(tokens[j]).balanceOf(address(this))
                        );
                    }
                    _userBalance[user][tokens[j]] -= int256(amounts[j]);
                    _decreaseTotalDeposited(tokens[j], amounts[j]);
                    IERC20(tokens[j]).safeTransfer(user, amounts[j]);
                }
            }
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function cancelStaleWithdrawals(uint256[] calldata _requestIds) external onlyRole(TELLER_ROLE) whenNotPaused {
        for (uint256 i = 0; i < _requestIds.length; ++i) {
            uint256 requestId = _requestIds[i];
            WithdrawalRequest storage req = _withdrawalRequests[requestId];

            if (_isWithdrawalExpired(req)) {
                _finalizeRequest(requestId, Status.Expired, ReasonCodes.REASON_EXPIRED);
            }
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function resolveDisputedWithdrawal(
        uint256 _requestId,
        bool _approve,
        uint256 _reasonCode
    )
        external
        onlyRole(GUARDIAN_ROLE)
        whenNotPaused
    {
        WithdrawalRequest storage req = _withdrawalRequests[_requestId];
        if (req.status != Status.Disputed) {
            revert InvalidStateForAction(_requestId, req.status);
        }

        if (_approve) {
            // Check guardian approval limits
            for (uint256 i = 0; i < req.tokens.length; ++i) {
                uint256 limit = _guardianApprovalLimits[msg.sender][req.tokens[i]];
                if (limit > 0 && req.amounts[i] > limit) {
                    revert GuardianApprovalLimitExceeded(req.tokens[i], req.amounts[i], limit);
                }
            }

            _updateStatus(_requestId, Status.Disputed, Status.Validated, ReasonCodes.REASON_MANUAL_OVERRIDE);
        } else {
            _finalizeRequest(_requestId, Status.Denied, _reasonCode);
        }
    }

    // ====================================================================
    // |                  Admin and Guardian Functions                    |
    // ====================================================================

    /// @inheritdoc ISynthetixDepositContract
    function addCollateral(address _token, CollateralConfig calldata _config) external onlyRole(OWNER_ROLE) {
        if (_token == address(0)) revert ZeroAddress();
        if (_config.globalMaximum == 0) revert InvalidInput();
        if (_config.userMaximum == 0) revert InvalidInput();
        if (_config.userMinimum > _config.userMaximum) revert InvalidInput();
        if (_config.withdrawalMinimum > _config.userMinimum) {
            revert InvalidInput();
        }
        if (_config.userMaximum > _config.globalMaximum) revert InvalidInput();

        _collateralConfigs[_token] = CollateralConfig({
            globalMaximum: _config.globalMaximum,
            userMinimum: _config.userMinimum,
            userMaximum: _config.userMaximum,
            withdrawalMinimum: _config.withdrawalMinimum,
            enabled: _config.enabled
        });

        emit CollateralAdded(_token);
        emit CollateralConfigUpdated(
            _token, _config.globalMaximum, _config.userMinimum, _config.userMaximum, _config.withdrawalMinimum
        );
    }

    /// @inheritdoc ISynthetixDepositContract
    function updateCollateralConfig(address _token, CollateralConfig calldata _config) external onlyRole(OWNER_ROLE) {
        if (!_collateralConfigs[_token].enabled) revert TokenNotSupported();
        if (_config.globalMaximum == 0) revert InvalidInput();
        if (_config.userMaximum == 0) revert InvalidInput();
        if (_config.userMinimum > _config.userMaximum) revert InvalidInput();
        if (_config.withdrawalMinimum > _config.userMinimum) {
            revert InvalidInput();
        }
        if (_config.userMaximum > _config.globalMaximum) revert InvalidInput();

        _collateralConfigs[_token] = CollateralConfig({
            globalMaximum: _config.globalMaximum,
            userMinimum: _config.userMinimum,
            userMaximum: _config.userMaximum,
            withdrawalMinimum: _config.withdrawalMinimum,
            enabled: _config.enabled
        });

        emit CollateralConfigUpdated(
            _token, _config.globalMaximum, _config.userMinimum, _config.userMaximum, _config.withdrawalMinimum
        );
    }

    /// @inheritdoc ISynthetixDepositContract
    function removeCollateral(address _token) external onlyRole(OWNER_ROLE) {
        _collateralConfigs[_token].enabled = false;
        emit CollateralRemoved(_token);
    }

    /// @inheritdoc ISynthetixDepositContract
    function setGuardianApprovalLimits(
        address _guardian,
        GuardianApprovalLimit[] calldata _limits
    )
        external
        onlyRole(OWNER_ROLE)
    {
        if (_guardian == address(0)) revert ZeroAddress();

        for (uint256 i = 0; i < _limits.length; ++i) {
            _guardianApprovalLimits[_guardian][_limits[i].token] = _limits[i].limit;
            emit GuardianApprovalLimitSet(_guardian, _limits[i].token, _limits[i].limit);
        }
    }

    /// @inheritdoc ISynthetixDepositContract
    function setWatcherQuorum(uint256 _quorum) external onlyRole(OWNER_ROLE) {
        uint256 watcherCount = getRoleMemberCount(WATCHER_ROLE);
        if (_quorum > watcherCount || _quorum == 0) revert InvalidInput();

        watcherQuorum = _quorum;
        emit WatcherQuorumSet(_quorum);
    }

    /// @inheritdoc ISynthetixDepositContract
    function setWithdrawalExpiryTimeout(uint256 _timeout) external onlyRole(OWNER_ROLE) {
        if (_timeout < 60) {
            // Withdrawal expiry should be at least 1 minute to allow for processing time
            revert InvalidInput();
        }
        withdrawalExpiryTimeout = _timeout;
        emit WithdrawalExpiryTimeoutSet(_timeout);
    }

    /**
     * @notice Grants a role to an account
     * @param role The role to grant
     * @param account The account to grant the role to
     * @dev OWNER_ROLE and MANAGER_ROLE are restricted to OWNER_ROLE only
     *      Other roles can be granted by MANAGER_ROLE
     */
    function grantRole(bytes32 role, address account) public override(AccessControlUpgradeable, IAccessControl) {
        if (role == OWNER_ROLE || role == MANAGER_ROLE) {
            _checkRole(OWNER_ROLE);
        } else {
            if (!hasRole(OWNER_ROLE, _msgSender())) {
                _checkRole(getRoleAdmin(role));
            }
        }
        super._grantRole(role, account);
    }

    /**
     * @notice Revokes a role from an account
     * @param role The role to revoke
     * @param account The account to revoke the role from
     * @dev OWNER_ROLE changes require OWNER_ROLE (timelock)
     *  Other roles can be revoked by MANAGER_ROLE (no timelock)
     */
    function revokeRole(bytes32 role, address account) public override(AccessControlUpgradeable, IAccessControl) {
        if (role == OWNER_ROLE || role == MANAGER_ROLE) {
            _checkRole(OWNER_ROLE);
        } else {
            if (!hasRole(OWNER_ROLE, _msgSender())) {
                _checkRole(getRoleAdmin(role));
            }
        }
        super._revokeRole(role, account);
    }

    /// @inheritdoc ISynthetixDepositContract
    function pauseAllWithdrawals() external onlyRole(GUARDIAN_ROLE) {
        withdrawalsGloballyPaused = true;
        emit GlobalWithdrawalsPaused();
    }

    /// @inheritdoc ISynthetixDepositContract
    function pauseAllDeposits() external onlyRole(GUARDIAN_ROLE) {
        depositsGloballyPaused = true;
        emit GlobalDepositsPaused();
    }

    /// @inheritdoc ISynthetixDepositContract
    function pauseWithdrawalsFor(address token) external onlyRole(GUARDIAN_ROLE) {
        tokenWithdrawalsPaused[token] = true;
        emit TokenSpecificWithdrawalsPaused(token);
    }

    /// @inheritdoc ISynthetixDepositContract
    function pauseDepositsFor(address token) external onlyRole(GUARDIAN_ROLE) {
        tokenDepositsPaused[token] = true;
        emit TokenSpecificDepositsPaused(token);
    }

    /// @inheritdoc ISynthetixDepositContract
    function unpauseWithdrawals() external onlyRole(OWNER_ROLE) {
        withdrawalsGloballyPaused = false;
        emit GlobalWithdrawalsUnpaused();
    }

    /// @inheritdoc ISynthetixDepositContract
    function unpauseDeposits() external onlyRole(OWNER_ROLE) {
        depositsGloballyPaused = false;
        emit GlobalDepositsUnpaused();
    }

    /// @inheritdoc ISynthetixDepositContract
    function unpauseWithdrawalsFor(address token) external onlyRole(OWNER_ROLE) {
        tokenWithdrawalsPaused[token] = false;
        emit TokenSpecificWithdrawalsUnpaused(token);
    }

    /// @inheritdoc ISynthetixDepositContract
    function unpauseDepositsFor(address token) external onlyRole(OWNER_ROLE) {
        tokenDepositsPaused[token] = false;
        emit TokenSpecificDepositsUnpaused(token);
    }

    /// @inheritdoc ISynthetixDepositContract
    function overrideRequestStatus(
        uint256 _requestId,
        Status _newStatus,
        uint256 _reasonCode
    )
        external
        onlyRole(OWNER_ROLE)
    {
        WithdrawalRequest storage req = _withdrawalRequests[_requestId];
        Status currentStatus = req.status;

        // Prevent overriding already finalized requests unless forcing a different final state
        if (_isFinalStatus(currentStatus)) {
            if (!_isFinalStatus(_newStatus)) {
                revert InvalidStateForAction(_requestId, currentStatus);
            }
        }

        // Handle transitions to final states
        if (_isFinalStatus(_newStatus)) {
            // If already in a final state, just update the status directly
            if (_isFinalStatus(currentStatus)) {
                req.status = _newStatus;
                req.processedTime = uint32(block.timestamp);
                req.reasonCode = uint16(_reasonCode);
                emit WithdrawalStatusChanged(_requestId, req.user, _newStatus, _reasonCode);
            } else {
                _finalizeRequest(_requestId, _newStatus, _reasonCode);
            }
        } else {
            // For non-final states, just update the status
            _updateStatus(_requestId, currentStatus, _newStatus, _reasonCode);
        }
    }

    // ====================================================================
    // |                      CoW Protocol Integration                   |
    // ====================================================================

    /**
     * @notice Approve CoW VaultRelayer to spend collateral tokens
     * @param _token Token to approve
     * @param _amount Amount to approve
     * @dev Only callable by OWNER_ROLE (timelock)
     */
    function approveCowVaultRelayer(address _token, uint256 _amount) external onlyRole(OWNER_ROLE) {
        if (!_collateralConfigs[_token].enabled) revert TokenNotSupported();

        IERC20(_token).forceApprove(COW_VAULT_RELAYER, _amount);

        emit CowVaultRelayerApproved(_token, _amount);
    }

    /**
     * @notice Emergency function to revoke all approvals for a token
     * @param _token Token to revoke approvals for
     * @dev Only callable by GUARDIAN_ROLE for emergency response
     */
    function emergencyRevokeApprovals(address _token) external onlyRole(GUARDIAN_ROLE) {
        IERC20(_token).forceApprove(COW_VAULT_RELAYER, 0);

        emit CowApprovalRevoked(_token);
    }

    /**
     * @notice Check current VaultRelayer allowance for a token
     * @param _token Token to check
     * @return Current approval amount
     */
    function getCowAllowance(address _token) external view returns (uint256) {
        return IERC20(_token).allowance(address(this), COW_VAULT_RELAYER);
    }

    // ====================================================================
    // |                      SLP Vault Integration                      |
    // ====================================================================

    /**
     * @notice Set the SLP Vault address authorized to pull USDT rewards
     * @param _vault Address of the SLP Vault contract
     * @dev Only callable by OWNER_ROLE
     */
    function setSLPVault(address _vault) external onlyRole(OWNER_ROLE) {
        if (_vault == address(0)) revert ZeroAddress();
        slpVault = _vault;
        emit SLPVaultSet(_vault);
    }

    /**
     * @notice Approve SLP Vault to spend USDT for reward distribution
     * @param _amount Amount of USDT to approve
     * @dev Only callable by OWNER_ROLE (timelock)
     */
    function approveSLPVault(uint256 _amount) external onlyRole(OWNER_ROLE) {
        if (slpVault == address(0)) revert ZeroAddress();

        IERC20(USDT).forceApprove(slpVault, _amount);

        emit SLPVaultApproved(_amount);
    }

    /**
     * @notice Check current SLP Vault allowance for USDT
     * @return Current approval amount
     */
    function getSLPVaultAllowance() external view returns (uint256) {
        if (slpVault == address(0)) return 0;
        return IERC20(USDT).allowance(address(this), slpVault);
    }

    /**
     * @notice Sets the slippage tolerance (in basis points) for CoW validation
     * @param _bps Basis points (1% = 100 bps). Must be <= 10_000 (100%).
     */
    function setSlippageToleranceBps(uint256 _bps) external onlyRole(OWNER_ROLE) {
        if (_bps > 10_000) revert InvalidInput();
        slippageToleranceBps = _bps;
        emit SlippageToleranceSet(_bps);
    }

    /**
     * @notice Sets the Chainlink USD price feed for a token (including USDT)
     * @param _token The token address
     * @param _aggregator The Chainlink aggregator address returning token/USD (8 decimals typical)
     */
    function setPriceFeed(address _token, address _aggregator) external onlyRole(OWNER_ROLE) {
        if (_token == address(0) || _aggregator == address(0)) {
            revert InvalidInput();
        }
        _priceFeedsUSD[_token].aggregator = _aggregator;
        emit PriceFeedSet(_token, _aggregator);
    }

    /**
     * @notice Sets the maximum staleness for Chainlink oracle data
     * @param _timeout Seconds after which oracle price is considered stale. 0 disables the check.
     */
    function setOracleStaleTimeout(uint256 _timeout) external onlyRole(OWNER_ROLE) {
        maxOracleStaleTimeout = _timeout;
        emit OracleStaleTimeoutSet(address(0), _timeout);
    }

    /**
     * @notice Configures a token-specific oracle staleness timeout
     * @param _token Token address the timeout applies to
     * @param _timeout Seconds after which oracle price is considered stale for the token. 0 disables the check.
     */
    function setOracleStaleTimeoutForToken(address _token, uint256 _timeout) external onlyRole(OWNER_ROLE) {
        _priceFeedsUSD[_token].staleTimeout = uint48(_timeout);
        emit OracleStaleTimeoutSet(_token, _timeout);
    }

    /**
     * @notice ERC-1271 signature validation for CoW Protocol orders
     * @param orderDigest The hash of the CoW swap order
     * @param signature ABI-encoded envelope carrying order params and the EOA signature
     * @return The ERC-1271 magic value if signature is valid
     * @dev Accepts only ABI-encoded envelope signatures. Raw ECDSA signatures are not supported.
     */
    function isValidSignature(
        bytes32 orderDigest,
        bytes calldata signature
    )
        external
        view
        override(IERC1271, ISynthetixDepositContract)
        returns (bytes4)
    {
        // ABI-encoded envelope with order metadata and EOA signature:
        // (CowOrder.Data, bytes eoaSignature)
        if (signature.length < MIN_ENVELOPE_LENGTH) revert InvalidEnvelope();

        (CowOrder.Data memory order, bytes memory eoaSignature) = abi.decode(signature, (CowOrder.Data, bytes));

        // Order validations
        // Here we follow the same order as validating as presented in the CowOrder.Data struct.

        // Token checks: sellToken MUST be supported collateral; buyToken MUST be USDT only
        if (!_collateralConfigs[address(order.sellToken)].enabled) {
            revert TokenNotSupported();
        }
        if (address(order.buyToken) != USDT) revert InvalidTradeParams();

        // Receiver check
        // Here we ensure that the receiver is address(this) to make sure the trader can't
        // steal from us.
        if (order.receiver != address(this)) {
            revert InvalidReceiver(order.receiver);
        }

        // Token amount validations
        if (order.sellAmount == 0 || order.buyAmount == 0) {
            revert InvalidTradeParams();
        }

        // Price validation using Chainlink if tolerance is set
        if (slippageToleranceBps > 0) {
            _checkPriceSlippage(address(order.sellToken), order.sellAmount, order.buyAmount);
        }

        // We intentionally do **NOT** check:
        //  - `order.validTo` as the validity time is enforced by CoW Protocol
        //  - `order.appData` as we trust the EOA signer to popualte the metadata correctly
        //    CAUTION: The EOA would be able to define hooks that could grief gas consumption as well
        //             as define arbitrary referrers / partners that would reduce surplus payable to
        //             the implementing protocol (Synthetix).
        // - `order.feeAmount` as this is a deprecated field in CoW Protocol and must be set to `0`.
        // - `order.kind` as the EOA is entrusted with determing if it is:
        //    * bytes32(keccak256("sell")) - trade fixed sellAmount, receive *minimum* buyAmount
        //    * bytes32(keccak256("buy"))  - trade *maximum* sellAmount, received *fixed* buyAmount
        // - `order.partiallyFillable` is delegated to the EOA

        // Ensure sell and buy balances are traded against ERC20 balances (not balancer vault)
        if (order.sellTokenBalance != CowOrder.BALANCE_ERC20) {
            revert InvalidTradeParams();
        }
        if (order.buyTokenBalance != CowOrder.BALANCE_ERC20) {
            revert InvalidTradeParams();
        }

        // Verify that the `orderDigest` corresponds to the `order` that we have been checking
        if (order.hash(COW_DOMAIN_SEPARATOR) != orderDigest) {
            revert InvalidTradeSignature();
        }

        // Verify the embedded EOA signature corresponds to an authorized trader
        address signer = ECDSA.recover(orderDigest, eoaSignature);
        if (!hasRole(AUTHORIZED_TRADER_ROLE, signer)) {
            revert UnauthorizedSigner();
        }

        return EIP1271_MAGICVALUE;
    }

    // ====================================================================
    // |                          Oracle Helpers                         |
    // ====================================================================

    /**
     * @notice Fetches and validates the latest price from a Chainlink feed.
     * @dev It checks for a positive price, a complete round, and feed-specific price staleness.
     * @param feedAddress The address of the Chainlink AggregatorV3Interface contract.
     * @param staleTimeout Maximum permitted age for the oracle data (0 disables the check).
     * @return price The validated price answer from the oracle.
     * @return decimals The number of decimals the price is reported in.
     */
    function _getValidatedOraclePrice(
        address feedAddress,
        uint256 staleTimeout
    )
        internal
        view
        returns (int256 price, uint8 decimals)
    {
        (
            uint80 roundId,
            int256 answer, // We don't need startedAt
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = AggregatorV3Interface(feedAddress).latestRoundData();

        // 1. Check for a valid, positive price
        if (answer <= 0) {
            revert InvalidOracleAnswer();
        }

        // 2. Check that the round is complete
        if (answeredInRound < roundId) {
            revert InvalidOracleAnswer(); // Or a more specific "IncompleteOracleRound" error
        }

        // 3. Check for stale data
        // The oracleStaleTimeout check prevents reverting if the feature is disabled (timeout = 0).
        if (staleTimeout > 0) {
            if (updatedAt == 0 || block.timestamp - updatedAt > staleTimeout) {
                revert OraclePriceStale(feedAddress, updatedAt);
            }
        }

        // 4. Return the validated data
        price = answer;
        decimals = AggregatorV3Interface(feedAddress).decimals();
    }

    /**
     * @notice Normalizes a value to 18 decimals (WAD representation).
     * @param value The raw value to normalize.
     * @param decimals The number of decimals of the raw value.
     * @return The value scaled to 1e18.
     */
    function _normalizeToWad(int256 value, uint8 decimals) internal pure returns (uint256) {
        if (decimals <= 18) {
            return uint256(value) * (10 ** (18 - decimals));
        } else {
            return uint256(value) / (10 ** (decimals - 18));
        }
    }

    /**
     * @notice Fetches and normalizes the USD prices for a given token and for USDT itself.
     * @param tokenFeed The Chainlink feed address for the token/USD pair.
     * @param tokenStaleTimeout Maximum allowed age for the token price data (0 disables the check).
     * @param usdtFeed The Chainlink feed address for the USDT/USD pair.
     * @param usdtStaleTimeout Maximum allowed age for the USDT price data (0 disables the check).
     * @return tokenUsd18 The token's price in USD, normalized to 18 decimals.
     * @return usdtUsd18 The USDT price in USD, normalized to 18 decimals.
     */
    function _getUsdPrices18(
        address tokenFeed,
        uint256 tokenStaleTimeout,
        address usdtFeed,
        uint256 usdtStaleTimeout
    )
        internal
        view
        returns (uint256 tokenUsd18, uint256 usdtUsd18)
    {
        // Get validated price data for the collateral token
        (int256 tokenAnswer, uint8 tokenDecimals) = _getValidatedOraclePrice(tokenFeed, tokenStaleTimeout);

        // Get validated price data for USDT
        (int256 usdtAnswer, uint8 usdtDecimals) = _getValidatedOraclePrice(usdtFeed, usdtStaleTimeout);

        // Normalize both prices to a common 18-decimal format
        tokenUsd18 = _normalizeToWad(tokenAnswer, tokenDecimals);
        usdtUsd18 = _normalizeToWad(usdtAnswer, usdtDecimals);
    }

    function _usdtPerTokenWad(address sellToken) internal view returns (uint256 usdtPerWad) {
        (address tokenFeed, uint256 tokenStaleTimeout) = _getPriceFeed(sellToken);
        (address usdtFeed, uint256 usdtStaleTimeout) = _getPriceFeed(USDT);

        (uint256 tokenUsd18, uint256 usdtUsd18) =
            _getUsdPrices18(tokenFeed, tokenStaleTimeout, usdtFeed, usdtStaleTimeout);
        // usdtPerToken scaled to WAD
        usdtPerWad = Math.mulDiv(tokenUsd18, WAD, usdtUsd18);
    }

    function _getPriceFeed(address token) private view returns (address feed, uint256 staleTimeout) {
        PriceFeedConfig storage config = _priceFeedsUSD[token];
        feed = config.aggregator;
        if (feed == address(0)) revert PriceFeedNotSet(token);

        staleTimeout = config.staleTimeout;
        if (staleTimeout == 0) {
            staleTimeout = maxOracleStaleTimeout;
        }
    }

    function _checkPriceSlippage(address sellToken, uint256 sellAmount, uint256 buyAmount) internal view {
        uint256 usdtPerTokenWad = _usdtPerTokenWad(sellToken);
        uint8 tokenDecimals = IERC20Metadata(sellToken).decimals();
        uint8 usdtTokenDecimals = USDT_DECIMALS;
        // expectedBuy in USDT smallest units
        uint256 expectedBuyWad = Math.mulDiv(sellAmount, usdtPerTokenWad, 10 ** tokenDecimals);
        uint256 expectedBuy = Math.mulDiv(expectedBuyWad, 10 ** usdtTokenDecimals, WAD);

        // Apply tolerance: min acceptable = expectedBuy * (1 - tol)
        uint256 minAcceptable = Math.mulDiv(expectedBuy, BPS_DENOMINATOR - slippageToleranceBps, BPS_DENOMINATOR);
        if (buyAmount < minAcceptable) revert InvalidTradeParams();
    }

    function grantAuthorizedTraderRole(address _trader) external {
        grantRole(AUTHORIZED_TRADER_ROLE, _trader);
        emit AuthorizedTraderRoleGranted(_trader);
    }

    /// @inheritdoc ISynthetixDepositContract
    function revokeAuthorizedTraderRole(address _trader) external {
        revokeRole(AUTHORIZED_TRADER_ROLE, _trader);
        emit AuthorizedTraderRoleRevoked(_trader);
    }

    // ====================================================================
    // |                         Internal Logic                         |
    // ====================================================================

    /**
     * @notice Returns true if the provided status is a terminal state
     * @param _status The status to evaluate
     */
    function _isFinalStatus(Status _status) internal pure returns (bool) {
        return _status == Status.Disbursed || _status == Status.Denied || _status == Status.Cancelled
            || _status == Status.Expired;
    }

    /**
     * @notice Checks if a withdrawal request has expired
     * @param req The withdrawal request to check
     * @return True if the request has expired, false otherwise
     * @dev Requests expire if not processed within withdrawalExpiryTimeout
     */
    function _isWithdrawalExpired(WithdrawalRequest storage req) internal view returns (bool) {
        return (req.status == Status.Requested || req.status == Status.Validated)
            && block.timestamp > req.requestTime + withdrawalExpiryTimeout;
    }

    /**
     * @notice Decreases the tracked total deposits for a token without underflowing
     * @param _token The collateral token being debited
     * @param _amount The amount to subtract
     * @dev Saturates at zero so external balance adjustments (e.g. swaps) do not brick withdrawals
     */
    function _decreaseTotalDeposited(address _token, uint256 _amount) internal {
        uint256 current = _totalDeposited[_token];
        unchecked {
            _totalDeposited[_token] = current <= _amount ? 0 : current - _amount;
        }
    }

    /**
     * @notice Updates the status of a withdrawal request with validation
     * @param _id The withdrawal request ID
     * @param _expected The expected current status
     * @param _new The new status to set
     * @param _reasonCode The reason for the status change
     * @dev Reverts if current status doesn't match expected
     */
    function _updateStatus(uint256 _id, Status _expected, Status _new, uint256 _reasonCode) internal {
        WithdrawalRequest storage req = _withdrawalRequests[_id];
        if (req.status != _expected) {
            revert InvalidStateForAction(_id, req.status);
        }
        req.status = _new;
        req.reasonCode = uint16(_reasonCode);
        emit WithdrawalStatusChanged(_id, req.user, _new, _reasonCode);
    }

    /**
     * @notice Finalizes a withdrawal request with a terminal status
     * @param _id The withdrawal request ID
     * @param _finalStatus The final status (Disbursed, Denied, Cancelled, or Expired)
     * @param _reasonCode The reason for the finalization
     * @dev Sets processedTime and clears user's active withdrawal
     */
    function _finalizeRequest(uint256 _id, Status _finalStatus, uint256 _reasonCode) internal {
        WithdrawalRequest storage req = _withdrawalRequests[_id];
        if (_isFinalStatus(req.status)) {
            revert AlreadyFinalized(_id);
        }
        req.status = _finalStatus;
        req.processedTime = uint32(block.timestamp);
        req.reasonCode = uint16(_reasonCode);
        _userActiveWithdrawalId[req.user] = 0;
        emit WithdrawalStatusChanged(_id, req.user, _finalStatus, _reasonCode);
    }

    // ====================================================================
    // |                       UUPS and Fallback                        |
    // ====================================================================

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @param newImplementation The address of the new implementation contract
     * @dev Required by UUPSUpgradeable, restricted to OWNER_ROLE
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(OWNER_ROLE) {
        // Intentionally left empty as authorization is handled by role check
    }

    /**
     * @notice Prevents accidental ETH deposits
     * @dev Reverts any ETH sent directly to the contract
     */
    receive() external payable {
        revert EthDepositsNotSupported();
    }
}
