// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.16;

interface IStakeCredit {
    function totalPooledBNB() external view returns (uint256);

    function getPooledBNBByShares(
        uint256 shares
    ) external view returns (uint256);

    function getSharesByPooledBNB(
        uint256 bnbAmount
    ) external view returns (uint256);

    function balanceOf(address delegator) external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function getPooledBNB(address account) external view returns (uint256);

    function claimableUnbondRequest(
        address delegator
    ) external view returns (uint256);

    function rewardRecord(uint256 dayIndex) external view returns (uint256);

    function distributeReward(uint64 commissionRate) external payable;

    function claim(
        address delegator,
        uint256 requestNumber
    ) external returns (uint256);

    function totalPooledBNBRecord(
        uint256 dayIndex
    ) external view returns (uint256);

    function delegate(address delegator) external payable returns (uint256);

    function undelegate(
        address delegator,
        uint256 shares
    ) external returns (uint256);

    function unbond(
        address delegator,
        uint256 shares
    ) external returns (uint256);
}
