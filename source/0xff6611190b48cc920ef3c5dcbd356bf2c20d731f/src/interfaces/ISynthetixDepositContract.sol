// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ISignatureTransfer } from "../interfaces/IPermit2.sol";

/**
 * @title ISynthetixDepositContract
 * @author 0xMithrandir
 * @notice Interface for the Synthetix Deposit Contract - a secure custody layer for the Synthetix perps exchange
 * @dev This interface defines the contract that handles all user deposits and manages a multi-stage, role-based
 * withdrawal process
 */
interface ISynthetixDepositContract {
    // ====================================================================
    // |                       Structs and Enums                        |
    // ====================================================================

    /**
     * @notice Represents the various states of a withdrawal request throughout its lifecycle
     * @dev State transitions are strictly controlled by role-based permissions
     */
    enum Status {
        Requested,
        Validated,
        Disbursed,
        Denied,
        Disputed,
        Cancelled,
        Expired
    }

    /**
     * @notice Contains all information about a withdrawal request
     * @dev Struct members:
     * - user: Address of the user who initiated the withdrawal (20 bytes)
     * - status: Current status of the withdrawal request (1 byte)
     * - watcherCount: Number of watchers who have validated this request (1 byte)
     * - requestTime: Timestamp when the withdrawal was requested (4 bytes)
     * - processedTime: Timestamp when the withdrawal was finalized (4 bytes)
     * - reasonCode: Code indicating the reason for a status change (2 bytes)
     * - tokens: Array of withdrawal tokens (32 bytes)
     * - tokens: Array of withdrawal token amounts (32 bytes)
     * @dev Gas optimized: Packed into 3 storage slots (20+1+1+4+4+2=32 bytes in slot 1, then 2x32 byte slots)
     */
    struct WithdrawalRequest {
        address user; // 20 bytes
        Status status; // 1 byte
        uint8 watcherCount; // 1 byte
        uint32 requestTime; // 4 bytes
        uint32 processedTime; // 4 bytes
        uint16 reasonCode; // 2 bytes
        // Slot boundary (32 bytes used, 0 bytes remaining)
        address[] tokens; // Array of token addresses
        uint256[] amounts; // Parallel array of amounts
    }

    /**
     * @notice Contains Permit2 signature details for gasless deposits
     * @dev Struct members:
     * - permit: The Permit2 transfer details
     * - signature: The user's signature authorizing the transfer
     */
    struct PermitDetails {
        ISignatureTransfer.PermitTransferFrom permit;
        bytes signature;
    }

    /**
     * @notice Contains collateral configuration for each supported token
     * @dev Struct members:
     * - enabled: Whether the collateral is currently enabled
     * - globalMaximum: Maximum total amount that can be deposited across all users
     * - userMinimum: Minimum amount per deposit for a user
     * - userMaximum: Maximum amount a single user can have deposited
     * - withdrawalMinimum: Minimum amount per withdrawal for a user
     * @dev Gas optimized: bool fits in first slot with potential future additions
     */
    struct CollateralConfig {
        bool enabled; // 1 byte (31 bytes remaining in slot 1)
        uint256 globalMaximum; // 32 bytes - slot 2
        uint256 userMinimum; // 32 bytes - slot 3
        uint256 userMaximum; // 32 bytes - slot 4
        uint256 withdrawalMinimum; // 32 bytes - slot 5
    }

    /**
     * @notice Contains guardian approval limits for different tokens
     * @dev Struct members:
     * - token: The token address
     * - limit: Maximum amount a guardian can approve for disputed withdrawals
     */
    struct GuardianApprovalLimit {
        address token;
        uint256 limit;
    }

    /**
     * @notice Represents a single deposit entry
     * @dev Struct members:
     * - token: The ERC20 token address to deposit
     * - amount: The amount of tokens to deposit
     * - beneficiary: The address to credit the deposit to (if different from sender)
     * - subAccountId: The sub-account ID for tracking purposes
     * - permitDetails: Optional Permit2 details for gasless deposits
     */
    struct DepositEntry {
        address token;
        uint256 amount;
        address beneficiary;
        uint256 subAccountId;
        PermitDetails permitDetails;
    }

    /**
     * @notice Represents a single withdrawal entry
     * @dev Struct members:
     * - tokens: The ERC20 token addresses to withdraw
     * - amounts: The amounts of tokens to withdraw
     * - beneficiary: The address to send the withdrawn tokens to
     */
    struct WithdrawalEntry {
        address[] tokens;
        uint256[] amounts;
        address beneficiary;
    }

    // ====================================================================
    // |                              Events                            |
    // ====================================================================

    /**
     * @notice Emitted when a user deposits assets into the contract
     * @param depositor The address of the depositor
     * @param beneficiary The address credited with the deposit
     * @param token The address of the deposited token
     * @param amount The amount of tokens deposited
     * @param subAccountId The sub-account ID for tracking
     */
    event AssetDeposited(
        address indexed depositor,
        address indexed beneficiary,
        address indexed token,
        uint256 amount,
        uint256 subAccountId
    );

    /**
     * @notice Emitted when a user requests a withdrawal
     * @param withdrawalId The unique ID of the withdrawal request
     * @param user The address of the user requesting withdrawal
     * @param tokens Array of token addresses in the withdrawal
     * @param amounts Array of token amounts in the withdrawal
     * @param timestamp The timestamp when the request was made
     */
    event WithdrawalRequested(
        uint256 indexed withdrawalId, address indexed user, address[] tokens, uint256[] amounts, uint256 timestamp
    );

    /**
     * @notice Emitted when a withdrawal request status changes
     * @param withdrawalId The unique ID of the withdrawal request
     * @param user The address of the user associated with the withdrawal
     * @param newStatus The new status of the withdrawal request
     * @param reasonCode The reason for the status change
     */
    event WithdrawalStatusChanged(
        uint256 indexed withdrawalId, address indexed user, Status indexed newStatus, uint256 reasonCode
    );

    /**
     * @notice Emitted when a new collateral token is added to the whitelist
     * @param token The address of the added token
     */
    event CollateralAdded(address indexed token);

    /**
     * @notice Emitted when a collateral token is removed from the whitelist
     * @param token The address of the removed token
     */
    event CollateralRemoved(address indexed token);

    /**
     * @notice Emitted when a collateral configuration is updated
     * @param token The address of the collateral token
     * @param globalMaximum The new global maximum deposit limit
     * @param userMinimum The new user minimum deposit limit
     * @param userMaximum The new user maximum deposit limit
     * @param withdrawalMinimum The new user minimum withdrawal limit
     */
    event CollateralConfigUpdated(
        address indexed token,
        uint256 globalMaximum,
        uint256 userMinimum,
        uint256 userMaximum,
        uint256 withdrawalMinimum
    );

    /**
     * @notice Emitted when guardian approval limits are updated
     * @param guardian The guardian address
     * @param token The token address
     * @param limit The new approval limit
     */
    event GuardianApprovalLimitSet(address indexed guardian, address indexed token, uint256 limit);

    /**
     * @notice Emitted when the watcher quorum threshold is updated
     * @param newQuorum The new quorum requirement
     */
    event WatcherQuorumSet(uint256 newQuorum);

    /**
     * @notice Emitted when the withdrawal expiry timeout is updated
     * @param newTimeout The new expiry timeout period in seconds
     */
    event WithdrawalExpiryTimeoutSet(uint256 newTimeout);

    /**
     * @notice Emitted when all deposits are paused globally
     */
    event GlobalDepositsPaused();

    /**
     * @notice Emitted when all withdrawals are paused globally
     */
    event GlobalWithdrawalsPaused();

    /**
     * @notice Emitted when global deposit pause is lifted
     */
    event GlobalDepositsUnpaused();

    /**
     * @notice Emitted when global withdrawal pause is lifted
     */
    event GlobalWithdrawalsUnpaused();

    /**
     * @notice Emitted when deposits are paused for a specific token
     * @param token The address of the paused token
     */
    event TokenSpecificDepositsPaused(address indexed token);

    /**
     * @notice Emitted when withdrawals are paused for a specific token
     * @param token The address of the paused token
     */
    event TokenSpecificWithdrawalsPaused(address indexed token);

    /**
     * @notice Emitted when token-specific deposit pause is lifted
     * @param token The address of the unpaused token
     */
    event TokenSpecificDepositsUnpaused(address indexed token);

    /**
     * @notice Emitted when token-specific withdrawal pause is lifted
     * @param token The address of the unpaused token
     */
    event TokenSpecificWithdrawalsUnpaused(address indexed token);

    /**
     * @notice Emitted when an authorized trader role is granted for CoW Protocol trading
     * @param trader The address that was granted the authorized trader role
     */
    event AuthorizedTraderRoleGranted(address indexed trader);

    /**
     * @notice Emitted when an authorized trader role is revoked for CoW Protocol trading
     * @param trader The address that had the authorized trader role revoked
     */
    event AuthorizedTraderRoleRevoked(address indexed trader);

    /**
     * @notice Emitted when the CoW Vault Relayer is approved to spend tokens
     * @param token The token address that was approved for spending
     * @param amount The amount approved for the CoW Vault Relayer
     */
    event CowVaultRelayerApproved(address indexed token, uint256 amount);

    /**
     * @notice Emitted when CoW Vault Relayer approval is revoked for a token
     * @param token The token address for which approval was revoked
     */
    event CowApprovalRevoked(address indexed token);

    /**
     * @notice Emitted when the SLP Vault address is set
     * @param vault The address of the SLP Vault contract
     */
    event SLPVaultSet(address indexed vault);

    /**
     * @notice Emitted when the SLP Vault is approved to spend USDT
     * @param amount The amount of USDT approved for the SLP Vault
     */
    event SLPVaultApproved(uint256 amount);

    /**
     * @notice Emitted when the slippage tolerance is set
     * @param newBps The new slippage tolerance in basis points
     */
    event SlippageToleranceSet(uint256 newBps);

    /**
     * @notice Emitted when the price feed is set
     * @param token The token address
     * @param aggregator The price feed aggregator address
     */
    event PriceFeedSet(address indexed token, address indexed aggregator);

    /**
     * @notice Emitted when the oracle staleness timeout is set
     * @param token The token address the timeout applies to (zero address for the global default)
     * @param newTimeout The new maximum allowed age (in seconds) for oracle data
     */
    event OracleStaleTimeoutSet(address indexed token, uint256 newTimeout);

    // ====================================================================
    // |                       Read-Only Functions                      |
    // ====================================================================

    /**
     * @notice Checks if a token is supported as collateral
     * @param _token The token address to check
     * @return True if the token is supported, false otherwise
     */
    function isCollateralSupported(address _token) external view returns (bool);

    /**
     * @notice Gets the collateral configuration for a token
     * @param _token The token address
     * @return The collateral configuration
     */
    function getCollateralConfig(address _token) external view returns (CollateralConfig memory);

    /**
     * @notice Gets the Chainlink price feed configured for a token
     * @param _token The token address
     * @return The configured aggregator address
     */
    function priceFeedsUSD(address _token) external view returns (address);

    /**
     * @notice Gets the total deposited amount for a specific token
     * @param _token The token address
     * @return The total amount deposited
     */
    function getTotalDeposited(address _token) external view returns (uint256);

    /**
     * @notice Gets the user's deposited amount for a specific token
     * @param _user The user address
     * @param _token The token address
     * @return The user's deposited amount (can be negative if losses exceed deposits)
     */
    function getUserBalance(address _user, address _token) external view returns (int256);

    /**
     * @notice Gets the guardian approval limit for a token
     * @param _guardian The guardian address
     * @param _token The token address
     * @return The approval limit
     */
    function getGuardianApprovalLimit(address _guardian, address _token) external view returns (uint256);

    /**
     * @notice Retrieves the details of a specific withdrawal request
     * @param _id The withdrawal request ID
     * @return The withdrawal request data
     */
    function getWithdrawalRequest(uint256 _id) external view returns (WithdrawalRequest memory);

    /**
     * @notice Gets the active withdrawal request ID for a user
     * @param _user The user's address
     * @return The ID of the user's active withdrawal request (0 if none)
     */
    function getActiveWithdrawalId(address _user) external view returns (uint256);

    /**
     * @notice Gets the current withdrawal request counter
     * @return The total number of withdrawal requests created
     */
    function getWithdrawalRequestCounter() external view returns (uint256);

    /**
     * @notice Gets all withdrawal request IDs for a specific user
     * @param _user The user address
     * @return Array of withdrawal request IDs created by the user
     */
    function getUserWithdrawalRequestIds(address _user) external view returns (uint256[] memory);

    // NOTE: getAllWithdrawalRequests and getWithdrawalRequestsByUser have been moved to
    // SynthetixDepositContractLens to reduce contract size. Use the lens contract for batch queries.

    /**
     * @notice Returns the SLP Vault address
     * @return Address of the SLP Vault contract
     */
    function slpVault() external view returns (address);

    // ====================================================================
    // |                     User-Facing Functions                      |
    // ====================================================================

    /**
     * @notice Deposits multiple tokens into the contract in a single transaction
     * @param _deposits Array of deposit entries specifying tokens, amounts, and sub-accounts
     * @dev Supports both standard ERC20 transfers and gasless deposits via Permit2
     */
    function deposit(DepositEntry[] calldata _deposits) external;

    /**
     * @notice Initiates a withdrawal request for multiple tokens
     * @param _withdrawals Array of withdrawal entries specifying tokens, amounts, and sub-accounts
     * @dev Users can only have one active withdrawal request at a time
     */
    function requestWithdrawal(WithdrawalEntry[] calldata _withdrawals) external;

    /**
     * @notice Allows users to cancel their own withdrawal request
     * @param _id The withdrawal request ID to cancel
     * @dev Can only be called before the request is validated by watchers
     */
    function cancelWithdrawal(uint256 _id) external;

    // ====================================================================
    // |             Role-Protected Functions (Withdrawal Lifecycle)    |
    // ====================================================================

    /**
     * @notice Batch rejects multiple withdrawal requests (RELAYER_ROLE only)
     * @param _ids Array of withdrawal request IDs to reject
     * @param _reasonCodes Array of reason codes for each rejection
     */
    function rejectWithdrawals(uint256[] calldata _ids, uint256[] calldata _reasonCodes) external;

    /**
     * @notice Batch disputes multiple withdrawal requests (RELAYER_ROLE or WATCHER_ROLE)
     * @param _ids Array of withdrawal request IDs to dispute
     * @param _reasonCodes Array of reason codes for each dispute
     */
    function disputeWithdrawals(uint256[] calldata _ids, uint256[] calldata _reasonCodes) external;

    /**
     * @notice Casts watcher votes to validate withdrawals (WATCHER_ROLE only)
     * @param _requestIds Array of withdrawal request IDs to validate
     * @dev Each request moves to Validated status once quorum is reached
     */
    function castWatcherVotes(uint256[] calldata _requestIds) external;

    /**
     * @notice Disburses funds for validated withdrawals (TELLER_ROLE only)
     * @param _requestIds Array of withdrawal request IDs to disburse
     * @dev Transfers all requested tokens to the respective users
     */
    function disburseWithdrawals(uint256[] calldata _requestIds) external;

    /**
     * @notice Cancels expired withdrawal requests (TELLER_ROLE only)
     * @param _requestIds Array of withdrawal request IDs to check and cancel if expired
     */
    function cancelStaleWithdrawals(uint256[] calldata _requestIds) external;

    /**
     * @notice Resolves a disputed withdrawal (GUARDIAN_ROLE only)
     * @param _requestId The withdrawal request ID to resolve
     * @param _approve True to validate the withdrawal, false to deny it
     * @param _reasonCode The reason for the denial (if applicable)
     */
    function resolveDisputedWithdrawal(uint256 _requestId, bool _approve, uint256 _reasonCode) external;

    // ====================================================================
    // |                  Admin and Guardian Functions                  |
    // ====================================================================

    /**
     * @notice Adds a new token to the supported collateral list (OWNER_ROLE only)
     * @param _token The token address to add
     * @param _config The initial collateral configuration
     */
    function addCollateral(address _token, CollateralConfig calldata _config) external;

    /**
     * @notice Updates the configuration for an existing collateral (OWNER_ROLE only)
     * @param _token The token address to update
     * @param _config The new collateral configuration
     */
    function updateCollateralConfig(address _token, CollateralConfig calldata _config) external;

    /**
     * @notice Removes a token from the supported collateral list (OWNER_ROLE only)
     * @param _token The token address to remove
     */
    function removeCollateral(address _token) external;

    /**
     * @notice Sets guardian approval limits for disputed withdrawals (OWNER_ROLE only)
     * @param _guardian The guardian address
     * @param _limits Array of token addresses and their approval limits
     */
    function setGuardianApprovalLimits(address _guardian, GuardianApprovalLimit[] calldata _limits) external;

    /**
     * @notice Sets the number of watcher votes required for validation (OWNER_ROLE only)
     * @param _quorum The new quorum requirement
     */
    function setWatcherQuorum(uint256 _quorum) external;

    /**
     * @notice Sets the expiry timeout for withdrawal requests (OWNER_ROLE only)
     * @param _timeout The new expiry timeout in seconds
     * @dev Requests expire if not processed within this time
     */
    function setWithdrawalExpiryTimeout(uint256 _timeout) external;

    /**
     * @notice Pauses all withdrawals globally (GUARDIAN_ROLE only)
     * @dev Emergency function to halt all withdrawal processing
     */
    function pauseAllWithdrawals() external;

    /**
     * @notice Pauses all deposits globally (GUARDIAN_ROLE only)
     * @dev Emergency function to halt all deposit processing
     */
    function pauseAllDeposits() external;

    /**
     * @notice Pauses withdrawals for a specific token (GUARDIAN_ROLE only)
     * @param token The token address to pause withdrawals for
     */
    function pauseWithdrawalsFor(address token) external;

    /**
     * @notice Pauses deposits for a specific token (GUARDIAN_ROLE only)
     * @param token The token address to pause deposits for
     */
    function pauseDepositsFor(address token) external;

    /**
     * @notice Unpauses global withdrawals (OWNER_ROLE only)
     * @dev Requires timelock execution for security
     */
    function unpauseWithdrawals() external;

    /**
     * @notice Unpauses global deposits (OWNER_ROLE only)
     * @dev Requires timelock execution for security
     */
    function unpauseDeposits() external;

    /**
     * @notice Unpauses withdrawals for a specific token (OWNER_ROLE only)
     * @param token The token address to unpause withdrawals for
     */
    function unpauseWithdrawalsFor(address token) external;

    /**
     * @notice Unpauses deposits for a specific token (OWNER_ROLE only)
     * @param token The token address to unpause deposits for
     */
    function unpauseDepositsFor(address token) external;

    /**
     * @notice Sets the maximum allowed age for oracle price data (OWNER_ROLE only)
     * @param _timeout The staleness timeout in seconds. 0 disables staleness checks.
     */
    function setOracleStaleTimeout(uint256 _timeout) external;

    /**
     * @notice Sets a token-specific oracle staleness timeout (OWNER_ROLE only)
     * @param _token The token the timeout applies to
     * @param _timeout The staleness timeout in seconds. 0 disables staleness checks for the token.
     */
    function setOracleStaleTimeoutForToken(address _token, uint256 _timeout) external;

    /**
     * @notice Force changes a withdrawal request status (OWNER_ROLE only)
     * @param _requestId The withdrawal request ID to modify
     * @param _newStatus The new status to set
     * @param _reasonCode The reason for the status override
     * @dev Emergency function requiring timelock execution
     */
    function overrideRequestStatus(uint256 _requestId, Status _newStatus, uint256 _reasonCode) external;

    // ====================================================================
    // |                         State Variables                        |
    // ====================================================================

    /**
     * @notice Returns the Permit2 contract address for gasless transfers
     * @return The Permit2 contract address
     */
    function PERMIT2() external view returns (address);

    /**
     * @notice Returns the role identifier for relayers
     * @return The RELAYER_ROLE bytes32 identifier
     */
    function RELAYER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for watchers
     * @return The WATCHER_ROLE bytes32 identifier
     */
    function WATCHER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for tellers
     * @return The TELLER_ROLE bytes32 identifier
     */
    function TELLER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for guardians
     * @return The GUARDIAN_ROLE bytes32 identifier
     */
    function GUARDIAN_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for the owner (timelock)
     * @return The OWNER_ROLE bytes32 identifier
     */
    function OWNER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for managers (non-timelocked admin)
     * @return The MANAGER_ROLE bytes32 identifier
     */
    function MANAGER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the role identifier for authorized traders
     * @return The AUTHORIZED_TRADER_ROLE bytes32 identifier
     */
    function AUTHORIZED_TRADER_ROLE() external view returns (bytes32);

    /**
     * @notice Returns the number of watcher votes required for validation
     * @return The current quorum requirement
     */
    function watcherQuorum() external view returns (uint256);

    /**
     * @notice Returns the expiry timeout for withdrawal requests
     * @return The expiry timeout in seconds
     */
    function withdrawalExpiryTimeout() external view returns (uint256);

    /**
     * @notice Returns whether deposits are globally paused
     * @return True if all deposits are paused, false otherwise
     */
    function depositsGloballyPaused() external view returns (bool);

    /**
     * @notice Returns whether withdrawals are globally paused
     * @return True if all withdrawals are paused, false otherwise
     */
    function withdrawalsGloballyPaused() external view returns (bool);

    /**
     * @notice Returns whether deposits are paused for a specific token
     * @param token The token address to check
     * @return True if deposits are paused for the token, false otherwise
     */
    function tokenDepositsPaused(address token) external view returns (bool);

    /**
     * @notice Returns whether withdrawals are paused for a specific token
     * @param token The token address to check
     * @return True if withdrawals are paused for the token, false otherwise
     */
    function tokenWithdrawalsPaused(address token) external view returns (bool);

    /**
     * @notice ERC-1271 signature validation for CoW Protocol orders
     * @param orderDigest The hash of the CoW swap order
     * @param eip1271Signature Encoded order data and signature from the authorized trader
     * @return The ERC-1271 magic value if signature is valid
     */
    function isValidSignature(bytes32 orderDigest, bytes calldata eip1271Signature) external view returns (bytes4);

    /**
     * @notice Grant the authorized trader role for CoW swap orders
     * @param _trader Address to grant the authorized trader role
     */
    function grantAuthorizedTraderRole(address _trader) external;

    /**
     * @notice Revoke the authorized trader role for CoW swap orders
     * @param _trader Address to revoke the authorized trader role from
     */
    function revokeAuthorizedTraderRole(address _trader) external;
}
