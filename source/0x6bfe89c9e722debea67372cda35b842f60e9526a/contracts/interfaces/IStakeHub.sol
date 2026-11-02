// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.16;

interface IStakeHub {
    function minDelegationBNBChange() external view returns (uint256);

    function DEAD_ADDRESS() external view returns (address);

    function LOCK_AMOUNT() external view returns (uint256);

    function BREATHE_BLOCK_INTERVAL() external view returns (uint256);

    function unbondPeriod() external view returns (uint256);

    function transferGasLimit() external view returns (uint256);

    function delegate(
        address operatorAddress,
        bool delegateVotePower
    ) external payable;

    function undelegate(address operatorAddress, uint256 shares) external;

    function redelegate(
        address srcValidator,
        address dstValidator,
        uint256 shares,
        bool delegateVotePower
    ) external;

    function claimBatch(
        address[] calldata operatorAddresses,
        uint256[] calldata requestNumbers
    ) external;

    function getValidatorCreditContract(
        address operatorAddress
    ) external view returns (address creditContract);

    function distributeReward(address) external payable;

    function getValidatorConsensusAddress(
        address
    ) external view returns (address);

    function redelegateFeeRate() external view returns (uint256);

    function REDELEGATE_FEE_RATE_BASE() external view returns (uint256);
}
