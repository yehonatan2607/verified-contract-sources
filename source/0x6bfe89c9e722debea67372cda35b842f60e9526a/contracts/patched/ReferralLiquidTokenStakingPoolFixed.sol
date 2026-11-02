// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@ankr.com/contracts/earn/LiquidTokenStakingPool.sol";
import "@ankr.com/contracts/interfaces/IReferralLiquidTokenStakingPool.sol";

contract ReferralLiquidTokenStakingPoolFixed is
    LiquidTokenStakingPool,
    IReferralLiquidTokenStakingPool
{
    function __ReferralPool_init() internal onlyInitializing {}

    /**
     * @dev Overrides LiquidTokenStakingPool#stakeBonds with additional param
     * @param code is a partner code for the Ankr Referral program
     */
    function stakeBondsWithCode(
        bytes32 code
    )
        external
        payable
        override
        nonReentrant
        bondStakingUnpaused
    {
        _stakeBonds(msg.sender, msg.value);
        emit ReferralCode(code);
    }

    /**
     * @dev Overrides LiquidTokenStakingPool#stakeCerts with additional param
     * @param code is a partner code for the Ankr Referral program
     */
    function stakeCertsWithCode(
        bytes32 code
    ) external payable override nonReentrant {
        _stakeCerts(msg.sender, msg.value);
        emit ReferralCode(code);
    }
}
