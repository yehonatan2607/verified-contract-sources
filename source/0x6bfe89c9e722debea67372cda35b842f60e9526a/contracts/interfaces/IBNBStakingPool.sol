// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.16;

interface IBNBStakingPoolErrors {
    error Validator_NotDelegatedTo();

    error Validator_NotValidator();

    error Validator_AlreadyExists();

    error Validator_NotExists();

    error Validator_ZeroAddress();

    error Delegation_AmountTooSmall();

    error Delegate_InsufficientBalance();

    error Undelegate_InsufficientBalance(uint256 amount);

    error Redelegate_WrongRelegateFee();

    error Redelegate_EqualValidators();

    error Swap_MinAmount();

    error Swap_InsufficientBalance();

    error Swap_Failed();

    error Swap_ExceedFlashPoolCapacity();

    error Treasury_ZeroAddress();

    error FlashUnstakeFeeCollected_ClaimFailed();

    error FlashUnstakeFee_WrongValue();
}

interface IBNBStakingPool is IBNBStakingPoolErrors {
    event Delegated(address indexed validatorAddress, uint256 amount);

    event Redelegated(
        address indexed validatorSrc,
        address indexed validatorDst,
        uint256 amount
    );

    event Undelegated(address indexed validatorAddress, uint256 amount);

    event StakingContractChanged(address oldValue, address newValue);

    event UndelegatedWithdrawn(uint256 amount);

    /// Rewards
    event DailyRewardsClaimed(uint256 rewards);

    /// Flash unstake

    event FlashUnstakeFeeChanged(uint256 oldValue, uint256 newValue);

    event FlashUnstakeFeeCollectedClaimed(
        address indexed claimerAddress,
        uint256 amount
    );

    event FlashPoolMinCapacityChanged(uint256 oldValue, uint256 newValue);

    event FlashFeeAmount(uint256 amount);

    event PartnersContractChanged(address oldValue, address newValue);

    /// Validators

    event ValidatorAdded(address indexed validatorAddress);

    event ValidatorRemoved(address indexed validatorAddress);
}
