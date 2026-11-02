// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";
import {BufferBase} from "./lib/BufferBase.sol";

contract BufferCoinbase is BufferBase {
    using SafeMath for uint256;
    
    constructor() public initializer {
        // Avoid leaving the implementation contract uninitialized.
    }

    // @dev minimum threshold to send
    function initialize(
        IGovernor _governor,
        uint256 threshold,
        address payable[] memory outputs,
        uint256[] memory splits,
        uint256[] memory thresholds
    ) public initializer {
        BufferBase._initialize(_governor, threshold, outputs, splits, thresholds);
    }

    function getBalance() public view override returns (uint256) {
        return address(this).balance;
    }

    function transfer(address destination, uint256 balance) internal override returns (bool) {
        (bool success, ) = destination.call{value: balance}("");
        return success;
    }

    function dispose(address payable beneficiary) external onlyAuthorizedChanger {
        selfdestruct(beneficiary);
    }

    function getToken() public view override returns (address) {
        return address(0);
    }

    function getAll()
        public
        view
        override
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            address,
            uint256
        )
    {
        return (getBalance(), _threshold, _splitTotal, _liquidated, address(0), _outputs.length);
    }
}
