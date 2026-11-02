// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ISynthetixDepositContract } from "./interfaces/ISynthetixDepositContract.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title Synthetix Deposit Contract Lens
 * @author 0xMithrandir
 * @notice Read-only helper contract for querying SynthetixDepositContract state
 * @dev This lens contract reduces the main contract's size by extracting view functions
 */
contract SynthetixDepositContractLens {
    /// @notice Address of the main SynthetixDepositContract
    ISynthetixDepositContract public immutable depositContract;

    /// @notice CoW Protocol VaultRelayer address
    address private constant COW_VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;

    /// @notice USDT token address on Ethereum mainnet
    address private constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    constructor(address _depositContract) {
        require(_depositContract != address(0), "Zero address");
        depositContract = ISynthetixDepositContract(_depositContract);
    }

    // ====================================================================
    // |                     Simple Getter Functions                    |
    // ====================================================================

    /**
     * @notice Check if a collateral token is supported
     * @param _token Token address to check
     * @return Whether the token is supported
     */
    function isCollateralSupported(address _token) external view returns (bool) {
        ISynthetixDepositContract.CollateralConfig memory config = depositContract.getCollateralConfig(_token);
        return config.enabled;
    }

    /**
     * @notice Get collateral configuration for a token
     * @param _token Token address
     * @return CollateralConfig struct
     */
    function getCollateralConfig(address _token)
        external
        view
        returns (ISynthetixDepositContract.CollateralConfig memory)
    {
        return depositContract.getCollateralConfig(_token);
    }

    /**
     * @notice Get total deposited amount for a token
     * @param _token Token address
     * @return Total deposited amount
     */
    function getTotalDeposited(address _token) external view returns (uint256) {
        return depositContract.getTotalDeposited(_token);
    }

    /**
     * @notice Get user balance for a specific token
     * @param _user User address
     * @param _token Token address
     * @return User's balance (can be negative if withdrawn more than deposited)
     */
    function getUserBalance(address _user, address _token) external view returns (int256) {
        return depositContract.getUserBalance(_user, _token);
    }

    /**
     * @notice Get guardian approval limit for a specific token
     * @param _guardian Guardian address
     * @param _token Token address
     * @return Approval limit
     */
    function getGuardianApprovalLimit(address _guardian, address _token) external view returns (uint256) {
        return depositContract.getGuardianApprovalLimit(_guardian, _token);
    }

    /**
     * @notice Get a specific withdrawal request
     * @param _id Withdrawal request ID
     * @return WithdrawalRequest struct
     */
    function getWithdrawalRequest(uint256 _id)
        external
        view
        returns (ISynthetixDepositContract.WithdrawalRequest memory)
    {
        return depositContract.getWithdrawalRequest(_id);
    }

    /**
     * @notice Get active withdrawal ID for a user
     * @param _user User address
     * @return Active withdrawal request ID (0 if none)
     */
    function getActiveWithdrawalId(address _user) external view returns (uint256) {
        return depositContract.getActiveWithdrawalId(_user);
    }

    /**
     * @notice Get total number of withdrawal requests
     * @return Total withdrawal request counter
     */
    function getWithdrawalRequestCounter() external view returns (uint256) {
        return depositContract.getWithdrawalRequestCounter();
    }

    /**
     * @notice Get price feed address for a token
     * @param _token Token address
     * @return Price feed address
     */
    function priceFeedsUSD(address _token) external view returns (address) {
        return depositContract.priceFeedsUSD(_token);
    }

    /**
     * @notice Check CoW VaultRelayer allowance for a token
     * @param _token Token address
     * @return Current approval amount
     */
    function getCowAllowance(address _token) external view returns (uint256) {
        return IERC20(_token).allowance(address(depositContract), COW_VAULT_RELAYER);
    }

    /**
     * @notice Check SLP Vault allowance for USDT
     * @return Current approval amount
     */
    function getSLPVaultAllowance() external view returns (uint256) {
        address slpVault = depositContract.slpVault();
        if (slpVault == address(0)) return 0;
        return IERC20(USDT).allowance(address(depositContract), slpVault);
    }

    // ====================================================================
    // |                    Batch Query Functions                       |
    // ====================================================================

    /**
     * @notice Get all withdrawal requests with pagination
     * @param _offset Starting index (0-based)
     * @param _limit Maximum number of requests to return
     * @return requests Array of withdrawal requests
     * @return ids Array of request IDs
     * @return total Total number of requests
     */
    function getAllWithdrawalRequests(
        uint256 _offset,
        uint256 _limit
    )
        external
        view
        returns (
            ISynthetixDepositContract.WithdrawalRequest[] memory requests,
            uint256[] memory ids,
            uint256 total
        )
    {
        total = depositContract.getWithdrawalRequestCounter();

        if (_offset >= total || _limit == 0) {
            return (new ISynthetixDepositContract.WithdrawalRequest[](0), new uint256[](0), total);
        }

        // Calculate actual return size
        uint256 returnSize = _limit;
        if (_offset + _limit > total) {
            returnSize = total - _offset;
        }

        requests = new ISynthetixDepositContract.WithdrawalRequest[](returnSize);
        ids = new uint256[](returnSize);

        // Direct access - O(limit) complexity instead of O(total)
        for (uint256 i = 0; i < returnSize; i++) {
            uint256 requestId = _offset + i + 1; // RequestIds start at 1
            requests[i] = depositContract.getWithdrawalRequest(requestId);
            ids[i] = requestId;
        }

        return (requests, ids, total);
    }

    /**
     * @notice Get withdrawal requests for a specific user with pagination
     * @param _user User address
     * @param _offset Starting index (0-based) into the user's request array
     * @param _limit Maximum number of requests to return
     * @return requests Array of user's withdrawal requests
     * @return ids Array of request IDs
     * @return total Total number of requests for this user
     */
    function getWithdrawalRequestsByUser(
        address _user,
        uint256 _offset,
        uint256 _limit
    )
        external
        view
        returns (
            ISynthetixDepositContract.WithdrawalRequest[] memory requests,
            uint256[] memory ids,
            uint256 total
        )
    {
        uint256[] memory userRequestIds = depositContract.getUserWithdrawalRequestIds(_user);
        total = userRequestIds.length;

        if (_offset >= total || _limit == 0) {
            return (new ISynthetixDepositContract.WithdrawalRequest[](0), new uint256[](0), total);
        }

        // Calculate actual return size
        uint256 returnSize = _limit;
        if (_offset + _limit > total) {
            returnSize = total - _offset;
        }

        requests = new ISynthetixDepositContract.WithdrawalRequest[](returnSize);
        ids = new uint256[](returnSize);

        // Direct access - O(returnSize) complexity instead of O(all requests)
        for (uint256 i = 0; i < returnSize; i++) {
            uint256 requestId = userRequestIds[_offset + i];
            ids[i] = requestId;
            requests[i] = depositContract.getWithdrawalRequest(requestId);
        }

        return (requests, ids, total);
    }

    /**
     * @notice Get multiple withdrawal requests by their IDs
     * @param _ids Array of withdrawal request IDs
     * @return requests Array of withdrawal requests corresponding to the IDs
     */
    function getWithdrawalRequests(uint256[] calldata _ids)
        external
        view
        returns (ISynthetixDepositContract.WithdrawalRequest[] memory requests)
    {
        requests = new ISynthetixDepositContract.WithdrawalRequest[](_ids.length);
        for (uint256 i = 0; i < _ids.length; i++) {
            requests[i] = depositContract.getWithdrawalRequest(_ids[i]);
        }
    }

    // ====================================================================
    // |                    Batch Balance Queries                       |
    // ====================================================================

    /**
     * @notice Get user balances for multiple tokens
     * @param _user User address
     * @param _tokens Array of token addresses
     * @return balances Array of balances corresponding to tokens
     */
    function getUserBalances(address _user, address[] calldata _tokens) external view returns (int256[] memory balances) {
        balances = new int256[](_tokens.length);
        for (uint256 i = 0; i < _tokens.length; i++) {
            balances[i] = depositContract.getUserBalance(_user, _tokens[i]);
        }
    }

}
