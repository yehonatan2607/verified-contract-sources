// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {IERC20} from "@openzeppelin/contracts-ethereum-package/contracts/token/ERC20/IERC20.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";
import {BufferBase} from "./lib/BufferBase.sol";

///////////////////////////////////////////
//
// !!!!!!!! WARNING - REQUIREMENT !!!!!!!!
//
///////////////////////////////////////////
//
// DO NOT USE THIS CONTRACT IMPLEMENTATION
// WITH INCOMPLETE ERC20 TOKEN
// IMPLEMENTATIONS.
//
// CONTRACT DISPOSAL AND TOKEN RETRIVAL
// RELIES ON TOKEN TRANSFER RETURN CODE
//
///////////////////////////////////////////
contract BufferToken is BufferBase {
    using SafeMath for uint256;

    IERC20 internal _token;

    constructor() public initializer {
        // Avoid leaving the implementation contract uninitialized.
    }
    
    // @dev minimum threshold to send
    function initialize(
        IGovernor _governor,
        IERC20 token,
        uint256 threshold,
        address payable[] memory outputs,
        uint256[] memory splits,
        uint256[] memory thresholds
    ) public initializer {
        require(token != IERC20(0), "Wrong token address");
        _token = token;
        BufferBase._initialize(_governor, threshold, outputs, splits, thresholds);
    }

    function getBalance() public view override returns (uint256) {
        return _token.balanceOf(address(this));
    }

    function transfer(address destination, uint256 balance) internal override returns (bool) {
        return _token.transfer(destination, balance);
    }

    function dispose(address payable beneficiary) external onlyAuthorizedChanger {
        uint256 balance = getBalance();
        bool success = _token.transfer(beneficiary, balance);
        require(success, "Failed to transfer the funds, aborting.");
        selfdestruct(beneficiary);
    }

    function getToken() public view override returns (address) {
        return address(_token);
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
        return (
            getBalance(),
            _threshold,
            _splitTotal,
            _liquidated,
            address(_token),
            _outputs.length
        );
    }

    function setToken(IERC20 token) public onlyAuthorizedChanger {
        require(getBalance() == 0, "Failed to set new token. Balance is not zero.");
        _token = token;
    }
}
