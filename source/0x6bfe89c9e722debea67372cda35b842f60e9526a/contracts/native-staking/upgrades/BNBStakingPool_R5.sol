// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import "../../patched/MixedLiquidTokenStakingPoolFixed.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import "../../interfaces/IStakingContract.sol";
import "../../interfaces/IBNBStakingPool.sol";
import "../../interfaces/IPartners.sol";
import "../../interfaces/IStakeHub.sol";
import "../../interfaces/IStakeCredit.sol";

contract BNBStakingPool_R5 is
    MixedLiquidTokenStakingPoolFixed,
    IBNBStakingPool
{
    using EnumerableSet for EnumerableSet.AddressSet;
    /**
     * Variables
     */
    uint256 internal constant _TEN_DECIMALS = 1e10;

    /// @dev BEP153 Native Staking
    /// @notice DEPRACATED after the Fusion Hardfork.
    IStakingContract internal _stakingContract;

    uint256 internal constant _FEE_MAX = 10000;

    /// @dev in %; the maximum is _FEE_MAX;
    uint256 internal _flashUnstakeFee;

    uint256 internal _flashUnstakeCollectedFee;

    uint256 internal _flashPoolMinCapacity;

    IPartners public partnersContract;

    /// @notice default BSC genesis contact address
    IStakeHub public constant stakingHub =
        IStakeHub(0x0000000000000000000000000000000000002002);

    EnumerableSet.AddressSet internal _validators;

    uint256 public pendingUndelegated;

    uint256 internal constant _VIRTUAL_AMOUNT_SHIFT = 1e3;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @param earnConfig contains major addresses for Ankr LiquidTokenStaking: consensus, governance, treasury...
     * @param distributeGasLimit defines the gas usage limit for distribuion rewards in _distributePendingRewards
     * @param stakingContract system Binance Native Staking contract: 0x0000000000000000000000000000000000002001
     */
    function initialize(
        IEarnConfig earnConfig,
        uint256 distributeGasLimit,
        IStakingContract stakingContract
    ) external initializer {
        __Ownable_init();
        __LiquidTokenStakingPool_init(earnConfig);
        __QueuePool_init(distributeGasLimit);
        _stakingContract = stakingContract;

        emit StakingContractChanged(address(0), address(stakingContract));
    }

    /* ======================================================================
     * ============================== DELEGATE ==============================
     * ====================================================================== */

    /**
     * @notice This function delegates to an optimal validator as per the backend service's choice.
     * @dev Executes by a backend service (consensus address).
     * @dev Ensures the amount meets the StakingHub.sol contract requirements.
     * @dev Checks that the validator is included in the `_validators` set.
     * @param validator The validator chosen by the backend service to delegate to.
     * @param amount The amount that is delegatable to the validator.
     * @param delegateVotePower Indicates whether the voting power should also be delegated to the validator.
     */
    function delegate(
        address validator,
        uint256 amount,
        bool delegateVotePower
    ) external onlyConsensus {
        if (validator == address(0)) revert Validator_ZeroAddress();
        if (!_validators.contains(validator)) revert Validator_NotExists();

        if (amount < stakingHub.minDelegationBNBChange())
            revert Delegation_AmountTooSmall();

        if (getFreeBalance() < amount) revert Delegate_InsufficientBalance();

        stakingHub.delegate{value: amount}(validator, delegateVotePower);

        emit Delegated(validator, amount);
    }

    /* ========================================================================
     * ============================== UNDELEGATE ==============================
     * ======================================================================== */

    /**
     * @notice Executes undelegation by a backend service using an optimal validator.
     * @dev Ensures the amount meets StakingHub.sol contract requirements.
     * @dev Verifies that the validator is in the _validators set.
     * @dev updates pendingUndelegated
     * @param validator is the validator chosen by the backend service to undelegate from
     * @param amount is the amount to undelegate from the validator
     */
    function undelegate(
        address validator,
        uint256 amount
    ) external nonReentrant onlyConsensus {
        if (!_validators.contains(validator)) revert Validator_NotExists();

        IStakeCredit credit = IStakeCredit(
            stakingHub.getValidatorCreditContract(validator)
        );
        uint256 shares = credit.getSharesByPooledBNB(amount);
        uint256 delegatedAmount = credit.balanceOf(address(this));
        if (delegatedAmount < shares)
            revert Undelegate_InsufficientBalance(delegatedAmount);

        stakingHub.undelegate(validator, shares);
        pendingUndelegated += amount;

        emit Undelegated(validator, amount);
    }

    /**
     * @notice Migrates the remaining undelegated requests from the deprecated Staking.sol following the Fusion Hardfork.
     */
    function migrationUndelegate(
        address[] memory validators
    ) external nonReentrant onlyConsensus {
        uint256 relayerFee = _stakingContract.getRelayerFee();
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            uint256 amount = _stakingContract.getDelegated(
                address(this),
                validator
            );
            _stakingContract.undelegate{value: relayerFee}(validator, amount);
            emit Undelegated(validator, amount);
        }
    }

    /* ========================================================================
     * ============================== REDELEGATE ==============================
     * ======================================================================== */

    /**
     * @dev Executes redelegation from one validator to another via a multi-sig wallet.
     * @dev Ensures the source validator's delegated amount is greater than the redelegation amount.
     * @notice msg.value is the amount to be paid to StakingHub as a redelegation fee.
     * @param validatorSrc The validator from which funds are being undelegated.
     * @param validatorDst The validator to which funds are being delegated.
     * @param amount The amount to be redelegated.
     * @param delegateVotePower Indicates whether the entire voting power should be delegated to validatorDst.
     */
    function redelegate(
        address validatorSrc,
        address validatorDst,
        uint256 amount,
        bool delegateVotePower
    ) external payable onlyGovernance {
        if (validatorSrc == validatorDst) revert Redelegate_EqualValidators();
        if (validatorSrc == address(0)) revert Validator_ZeroAddress();
        if (validatorDst == address(0)) revert Validator_ZeroAddress();

        if (amount < stakingHub.minDelegationBNBChange())
            revert Delegation_AmountTooSmall();

        uint256 shares = IStakeCredit(
            stakingHub.getValidatorCreditContract(validatorSrc)
        ).getSharesByPooledBNB(amount);

        uint256 delegatedAmount = IStakeCredit(
            stakingHub.getValidatorCreditContract(validatorSrc)
        ).balanceOf(address(this));
        if (delegatedAmount < shares)
            revert Undelegate_InsufficientBalance(delegatedAmount);

        if (getRedelegationFee(amount) > msg.value)
            revert Redelegate_WrongRelegateFee();

        stakingHub.redelegate(
            validatorSrc,
            validatorDst,
            shares,
            delegateVotePower
        );

        emit Redelegated(validatorSrc, validatorDst, amount);
    }

    /* ==========================================================================
     * ============================== USER UNSTAKE ==============================
     * ========================================================================== */

    /**
     * @dev Rewrites the function from the MixedLiquidTokenStakingPoolFixed.sol
     * @dev Disallows immediate/flash unstaking for all users.
     * @dev Users wishing to unstake immediately should use the `swap()` function instead.
     */
    function _afterUnstake(
        address ownerAddress,
        address receiverAddress,
        uint256 amount
    ) internal virtual override {
        _addIntoQueue(ownerAddress, receiverAddress, amount);
    }

    /* ============================================================================
     * ============================ DISTRIBUTE REWARDS ============================
     * ============================================================================ */

    /**
     * @notice Migrates the remaining undelegated requests from Staking.sol, which was deprecated after the Fusion update.
     */
    function migrationWithdraw() external onlyConsensus nonReentrant {
        _stakingContract.claimUndelegated();
    }

    /**
     * @notice Withdraws the undelegated requests from the StakingHub.sol to the pool(this address).
     * @dev It executes by the backend service.
     * @dev updates `pendingUndelegated`.
     */
    function withdrawUndelegated(
        address[] calldata validators
    ) external onlyConsensus nonReentrant {
        uint256 balanceInit = address(this).balance;

        uint256[] memory requestNumbers = new uint256[](validators.length);
        stakingHub.claimBatch(validators, requestNumbers);

        uint256 claimedAmount = address(this).balance - balanceInit;
        pendingUndelegated -= claimedAmount;

        emit UndelegatedWithdrawn(claimedAmount);
    }

    /**
     * @notice Withdraws undelegated requests from StakingHub.sol to the pool (this address),
     * @notice Distributes the claimed amount among users who have made unstake requests.
     * @dev Executed by the backend service.
     * @dev Updates the `pendingUndelegated`.
     */
    function withdrawAndDistributePendingRewards(
        address[] calldata validators
    ) external payable onlyConsensus nonReentrant {
        uint256 balanceInit = address(this).balance;

        uint256[] memory requestNumbers = new uint256[](validators.length);
        stakingHub.claimBatch(validators, requestNumbers);

        uint256 claimedAmount = address(this).balance - balanceInit;
        pendingUndelegated -= claimedAmount;

        _distributePendingRewards();
    }

    /**
     * @notice Functions similarly to `withdrawAndDistributePendingRewards()` but doesn't involve claiming from StakingHub.sol.
     * @dev This function may be used for emergency distributions.
     */
    function distributePendingRewards()
        external
        payable
        onlyConsensus
        nonReentrant
    {
        _distributePendingRewards();
    }

    /* ============================================================================
     * ================================ FLASH POOL ================================
     * ============================================================================ */

    /**
     * @notice Serves the Flash Unstake functionality.
     * @notice The user receives the unstaked BNB immediately.
     * @dev Charges an additional fee.
     */
    function swap(
        uint256 shares,
        address receiverAddress
    ) external nonReentrant {
        address ownerAddress = msg.sender;
        uint256 amount = _certificateToken.sharesToBonds(shares);
        if (amount < getMinUnstake()) revert Swap_MinAmount();

        shares = _certificateToken.bondsToShares(amount);

        if (_certificateToken.balanceOf(ownerAddress) < shares)
            revert Swap_InsufficientBalance();

        uint256 unstakeFeeAmt = (amount * _flashUnstakeFee) / _FEE_MAX;
        amount -= unstakeFeeAmt;
        _flashUnstakeCollectedFee += unstakeFeeAmt;
        // check the restrictions on flash unstake
        if (amount > getFlashPoolCapacity())
            revert Swap_ExceedFlashPoolCapacity();

        // burn the input amount of shares
        _certificateToken.burn(ownerAddress, shares);
        // send the amount: sharesToBonds(shares) - flashUnstakeFee
        bool result = _unsafeTransfer(receiverAddress, amount, false);
        if (!result) revert Swap_Failed();

        emit FlashFeeAmount(unstakeFeeAmt);
        emit Unstaked(ownerAddress, receiverAddress, amount, shares, false);
    }

    /**
     * @notice Withdraws the FlashPool fees(swap() function) to the treasury.
     * @dev Can be executed by anyone.
     */
    function claimFlashUnstakeFeeCollected() external nonReentrant {
        address treasuryAddress = _earnConfig.getTreasuryAddress();
        if (treasuryAddress == address(0)) revert Treasury_ZeroAddress();

        uint256 amount = _flashUnstakeCollectedFee;
        _flashUnstakeCollectedFee = 0;
        bool result = _unsafeTransfer(treasuryAddress, amount, false);
        if (!result) revert FlashUnstakeFeeCollected_ClaimFailed();

        emit FlashUnstakeFeeCollectedClaimed(msg.sender, amount);
    }

    /* =======================================================================
     * ====================== Rewards(from Staking.sol) ======================
     * ======================================================================= */

    /**
     * @notice Claims the daily pool's rewards.
     * @notice DEPRECATED after the Fusion HardFork
     * @dev Previously, this function had to be executed daily by everyone,
     * @dev Though it was usually performed by the backend service.
     */
    function claimDailyRewards() external nonReentrant {
        uint256 rewards = _stakingContract.claimReward();
        _afterClaimRewards(rewards);

        emit DailyRewardsClaimed(rewards);
    }

    /**
     * @dev Transfers the BNBStaking pool's fees to the referral partners contract.
     */
    function _afterClaimRewards(uint256 dailyRewards) internal virtual {
        uint256 referralRewards = (dailyRewards *
            partnersContract.percentOfDailyRewards()) / 100;
        bool result = _unsafeTransfer(
            address(partnersContract),
            referralRewards,
            true
        );
        require(result, "BNBStakingPool: failed to send referral rewards");
    }

    /* ======================================================================
     * ================================ VIEW ================================
     * ====================================================================== */

    function getSupportedValidators() public view returns (address[] memory) {
        return _validators.values();
    }

    /**
     * @dev Returns the total amount delegated in the StakingHub via the pool.
     */
    function getTotalDelegated() public view returns (uint256 amount) {
        uint256 len = _validators.length();
        for (uint256 i = 0; i < len; ) {
            address credit = stakingHub.getValidatorCreditContract(
                _validators.at(i)
            );
            if (credit == address(0)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            amount += IStakeCredit(credit).getPooledBNB(address(this));
            unchecked {
                ++i;
            }
        }
        return amount;
    }

    function isAbleToUnstake(uint256 amount) public view returns (bool) {
        return getTotalDelegated() + getFreeBalance() >= amount;
    }

    /**
     * @dev This method is overridden to take into account the _flashUnstakeCollectedFee and the _flashPoolMinCapacity.
     */
    function getFreeBalance() public view override returns (uint256) {
        uint256 occupiedBalance = getStashedForManualClaims() +
            _flashUnstakeCollectedFee +
            _flashPoolMinCapacity;
        return
            address(this).balance < occupiedBalance
                ? 0
                : address(this).balance - occupiedBalance;
    }

    function getFlashPoolCapacity() public view returns (uint256) {
        uint256 occupiedBalance = getStashedForManualClaims() +
            _flashUnstakeCollectedFee;
        return
            address(this).balance < occupiedBalance
                ? 0
                : address(this).balance - occupiedBalance;
    }

    function getFlashUnstakeFee() public view returns (uint256) {
        return _flashUnstakeFee;
    }

    function getFlashUnstakeCollectedFee() public view returns (uint256) {
        return _flashUnstakeCollectedFee;
    }

    function getFlashPoolMinCapacity() public view returns (uint256) {
        return _flashPoolMinCapacity;
    }

    /**
     * @notice Calculates the native ratio.
     * @dev Available after the Fusion Hardfork.
     */
    function getRatio() public view returns (uint256) {
        uint256 totalShares = _certificateToken.totalSupply();
        uint256 totalDelegated = getTotalDelegated();
        if (totalShares == 0) return 1e18;

        uint256 virtualShares = totalShares + _VIRTUAL_AMOUNT_SHIFT;
        uint256 virtualAmount = totalDelegated +
            getFreeBalance() +
            _flashPoolMinCapacity +
            pendingUndelegated -
            getTotalPendingUnstakes() +
            _VIRTUAL_AMOUNT_SHIFT;

        return (virtualShares * 1e18) / (virtualAmount);
    }

    /**
     * @notice Calculates the redelegation fee for the `redelegate` function.
     * @dev Becomes available after the Fusion Hardfork.
     */
    function getRedelegationFee(uint256 amount) public view returns (uint256) {
        return
            (amount * stakingHub.redelegateFeeRate()) /
            (stakingHub.REDELEGATE_FEE_RATE_BASE());
    }

    /**
     * @notice Calculates the ratio natively.
     * @dev Available after the Fusion Hardfork.
     */
    function getClaimableUndelegateRequests()
        public
        view
        returns (address[] memory, uint256[] memory)
    {
        uint256 index;
        uint256 numOfValidators = _validators.length();
        address[] memory validators = new address[](numOfValidators);
        uint256[] memory numOfRequests = new uint256[](numOfValidators);

        for (uint256 i = 0; i < numOfValidators; ) {
            address validatorAddress = _validators.at(i);
            address credit = stakingHub.getValidatorCreditContract(
                validatorAddress
            );
            unchecked {
                ++i;
            }
            if (credit == address(0)) continue;

            uint256 number = IStakeCredit(credit).claimableUnbondRequest(
                address(this)
            );
            if (number == 0) continue;

            validators[index] = validatorAddress;
            numOfRequests[index] = number;
            ++index;
        }

        // decrease arrays
        if (validators.length - index > 0) {
            assembly {
                mstore(validators, index)
                mstore(numOfRequests, index)
            }
        }

        return (validators, numOfRequests);
    }

    /* ======================================================================
     * ============================== SETTINGS ==============================
     * ====================================================================== */

    function setFlashUnstakeFee(uint256 newValue) external onlyGovernance {
        if (newValue >= _FEE_MAX) revert FlashUnstakeFee_WrongValue();
        uint256 oldValue = _flashUnstakeFee;
        _flashUnstakeFee = newValue;

        emit FlashUnstakeFeeChanged(oldValue, newValue);
    }

    function setFlashPoolMinCapacity(uint256 newValue) external onlyGovernance {
        uint256 oldValue = _flashPoolMinCapacity;
        _flashPoolMinCapacity = newValue;

        emit FlashPoolMinCapacityChanged(oldValue, newValue);
    }

    function addValidators(
        address[] memory validatorAddresses
    ) external onlyGovernance {
        uint256 numOfValidators = validatorAddresses.length;
        for (uint256 i = 0; i < numOfValidators; ) {
            _addValidator(validatorAddresses[i]);
            unchecked {
                ++i;
            }
        }
    }

    function addValidator(address validatorAddress) public onlyGovernance {
        _addValidator(validatorAddress);
    }

    function _addValidator(address validatorAddress) internal {
        if (validatorAddress == address(0)) revert Validator_ZeroAddress();
        if (_validators.contains(validatorAddress))
            revert Validator_AlreadyExists();

        address creditContract = stakingHub.getValidatorCreditContract(
            validatorAddress
        );
        if (creditContract == address(0)) revert Validator_NotValidator();

        _validators.add(validatorAddress);

        emit ValidatorAdded(validatorAddress);
    }

    function removeValidator(address validatorAddress) external onlyGovernance {
        if (validatorAddress == address(0)) revert Validator_ZeroAddress();
        if (!_validators.contains(validatorAddress))
            revert Validator_NotExists();

        _validators.remove(validatorAddress);

        emit ValidatorRemoved(validatorAddress);
    }

    /// @dev Receives unstakes/rewards from Staking.sol
    receive() external payable override {}
}
