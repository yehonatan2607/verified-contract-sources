// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {MocToken} from "@moc/periphery/contracts/MocToken.sol";
import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {Initializable} from "@openzeppelin/contracts-ethereum-package/contracts/Initializable.sol";
import {Governed} from "@moc/periphery/contracts/moc-governance/Governance/Governed.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";

//
// The coiner contract will mint a target amount of tokens in
// two stages: the first where it will output a fraction of the remaining tokens on each step,
// and a second one where it will output a constant amount per step until the total
// target amount is reached.
//
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
contract Coiner is Initializable, Governed {
    using SafeMath for uint256;

    uint256 public constant PERCENT_DIVISOR = 10000; // Two decimal digits of precision.

    MocToken private _token;
    uint256 private _firstStagePercent;
    uint256 private _secondStageConstant;
    address private _destination;
    uint256 private _totalMintTarget;
    uint256 private _remainingToMint;
    uint256 private _stage2BeginThreshold;
    // Deprecated when Coiner scheduling moved from blocks to timestamps.
    // These historical slots are retained only to preserve the proxy storage layout.
    uint256 private _deprecatedMintBlockInterval;
    uint256 private _deprecatedNextMintFromBlock;

    // First unused storage word after the deployed Coiner layout.
    uint256 private _mintTimestampInterval;
    uint256 private _nextMintAt;

    event Minted(uint256 amount, uint256 remaining, uint8 stage);

    constructor() public initializer {
        // Avoid leaving the implementation contract uninitialized.
    }

    /** @notice Initialize this contract 
        @param _governor The governor address 
        @param token The MOC token address to mint
        @param destination Output account address.
        @param totalMintTarget   How many tokens will be minted for the destination address
        @param firstStagePercent The % of remaining tokens that the contract will output on each "mintStep" call in stage I. Use two decimals of precision N.NN
        @param secondStageConstant  The constant amount of  tokens that the contract will output on each "mintStep" call
                                    in stage II until target is reached.
        @param stage2BeginThreshold A cut-off value where the constant emission stage II starts
    uint256 private _stage2BeginThreshold;
        */
    function initialize(
        IGovernor _governor,
        address token,
        address destination,
        uint256 totalMintTarget,
        uint256 firstStagePercent,
        uint256 secondStageConstant,
        uint256 stage2BeginThreshold
    ) public initializer() {
        require(token != address(0), "Token address null");
        require(destination != address(0), "Destination address null");
        require(totalMintTarget > 0, "Total tokens to mint cannot be zero");
        require(firstStagePercent > 0 && firstStagePercent < 10000, "Pct must be (1..10000)");
        require(
            secondStageConstant > 0 && secondStageConstant < totalMintTarget,
            "Stage 2 constant out of range"
        );
        require(stage2BeginThreshold > 0, "Stage-2 threshold must be positive");
        require(stage2BeginThreshold < totalMintTarget, "Must be less than mint target");

        _token = MocToken(token);
        _firstStagePercent = firstStagePercent;
        _secondStageConstant = secondStageConstant;
        _destination = destination;
        _stage2BeginThreshold = stage2BeginThreshold;
        _totalMintTarget = totalMintTarget;
        _remainingToMint = totalMintTarget;
        // Simple average Gregorian month: 365 days divided by 12.
        _mintTimestampInterval = 30 days + 10 hours;
        _nextMintAt = block.timestamp;

        Governed._initialize(_governor);
    }

    /// @notice Returns true if conditions for minting are satisfied.
    function readyToMint() public view returns (bool) {
        return
            (_remainingToMint > 0) &&
            (block.timestamp >= _nextMintAt) &&
            (_token.owner() == address(this));
    }

    /// @notice Triggers a minting step, if enough time has elapsed.
    //          If there is zero tokens remaining, it will do nothing.
    function mintStep() external {
        require(readyToMint(), "Cannot mint at this time");
        uint256 mintAmount = 0;
        uint8 st;
        if (_remainingToMint > _stage2BeginThreshold) {
            // Stage 1 (fractional)
            st = 1;
            mintAmount = _remainingToMint.mul(_firstStagePercent).div(PERCENT_DIVISOR);
        } else {
            // Stage 2 (constant-emission)
            st = 2;
            mintAmount = min(_secondStageConstant, _remainingToMint);
        }
        _remainingToMint = _remainingToMint.sub(mintAmount);
        _nextMintAt = block.timestamp.add(_mintTimestampInterval);
        _token.mint(address(this), mintAmount);
        bool success = _token.transfer(_destination, mintAmount);
        require(success, "Failed to transfer the funds, aborting.");
        emit Minted(mintAmount, _remainingToMint, st);
    }

    /** Internal functions */

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a < b) ? a : b;
    }

    // --- Getters ---

    /// @notice Returns the % of remaining tokens that the contract will output on each "mintStep" call in stage I
    function getFirstStagePercent() external view returns (uint256) {
        return _firstStagePercent;
    }

    /// @notice The constant amount of  tokens that the contract will output on each "mintStep" call
    /// in stage II until target is reached.
    function getSecondStageConstant() external view returns (uint256) {
        return _secondStageConstant;
    }

    /// @notice Output account address.
    function getDestination() external view returns (address) {
        return _destination;
    }

    /// @notice How many tokens will be minted for this address
    function getTotalMintTarget() external view returns (uint256) {
        return _totalMintTarget;
    }

    /// @notice Returns the remaining amount to mint.
    function getRemainingToMint() external view returns (uint256) {
        return _remainingToMint;
    }

    /// @notice Returns the cut-off value where the constant emission stage II starts
    function getStage2BeginThreshold() external view returns (uint256) {
        return _stage2BeginThreshold;
    }

    /// @notice Returns the timestamp from which the next mint step can be issued.
    function getNextMintAt() external view returns (uint256) {
        return _nextMintAt;
    }

    /// @notice Returns the minimum number of seconds between minting steps.
    function getMintTimestampInterval() external view returns (uint256) {
        return _mintTimestampInterval;
    }

    /**
     * @notice Sets the first timestamp-based mint due date once, through the
     *         governance changer that upgrades the proxy.
     */
    function initializeMintSchedule(uint256 nextMintAt, uint256 mintTimestampInterval)
        public
        onlyAuthorizedChanger()
    {
        require(nextMintAt > 0, "Mint timestamp must be positive");
        require(mintTimestampInterval > 0, "Mint interval must be positive");
        require(
            _nextMintAt == 0 && _mintTimestampInterval == 0,
            "Mint schedule already initialized"
        );
        _mintTimestampInterval = mintTimestampInterval;
        _nextMintAt = nextMintAt;
    }

    function setMintTimestampInterval(uint256 mintTimestampInterval)
        public
        onlyAuthorizedChanger()
    {
        require(mintTimestampInterval > 0, "Mint interval must be positive");
        _mintTimestampInterval = mintTimestampInterval;
    }

    function setStage2BeginThreshold(uint256 threshold) public onlyAuthorizedChanger() {
        _stage2BeginThreshold = threshold;
    }

    function setTotalMintTarget(uint256 totalMintTarget) public onlyAuthorizedChanger() {
        _totalMintTarget = totalMintTarget;
    }

    function setDestination(address destination) public onlyAuthorizedChanger() {
        _destination = destination;
    }

    function setSecondStageConstant(uint256 secondStageConstant) public onlyAuthorizedChanger() {
        _secondStageConstant = secondStageConstant;
    }

    function setFirstStagePercent(uint256 firstStagePercent) public onlyAuthorizedChanger() {
        _firstStagePercent = firstStagePercent;
    }

    function transferTokenOwnership(address newOwner) public onlyAuthorizedChanger() {
        _token.transferOwnership(newOwner);
    }
}
