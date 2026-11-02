// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {Initializable} from "@openzeppelin/contracts-ethereum-package/contracts/Initializable.sol";
import {Governed} from "@moc/periphery/contracts/moc-governance/Governance/Governed.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";

abstract contract BufferBase is Initializable, Governed {
    using SafeMath for uint256;

    event PaymentReceive(address payable indexed output, uint256 amount);
    event PaymentSent(address payable indexed output, uint256 amount);

    // @dev Single output
    struct Output {
        address payable output;
        uint256 split;
        uint256 threshold;
        uint256 balance;
    }

    // @dev Outputs
    Output[] internal _outputs;
    // @dev Sum of individual splits
    uint256 internal _splitTotal;
    uint256 internal _liquidated;
    uint256 internal _threshold;
    uint256 public constant PRECISION = 10**18;

    // @dev minimum threshold to send
    function _initialize(
        IGovernor _governor,
        uint256 threshold,
        address payable[] memory outputs,
        uint256[] memory splits,
        uint256[] memory thresholds
    ) internal {
        Governed._initialize(_governor);
        require(outputs.length == splits.length, "Lengths should match");
        _threshold = threshold;
        for (uint256 i = 0; i < outputs.length; i += 1) {
            _addOutput(outputs[i], splits[i], thresholds[i]);
        }
    }

    function getBalance() public view virtual returns (uint256);

    function transfer(address destination, uint256 balance) internal virtual returns (bool);

    function liquidate() public {
        uint256 balance = getBalance();
        uint256 toLiquidate = getLiquidated();
        uint256 amount = balance.sub(toLiquidate);
        require(isLiquidable(), "Buffer unliquidated ammount is not above buffer threshold");
        for (uint256 i = 0; i < _outputs.length; i += 1) {
            _outputs[i].balance = _outputs[i].balance.add(
                amount.mul(_outputs[i].split).div(_splitTotal)
            );
        }
        _liquidated = balance;
    }

    function flush(uint256 i) public {
        uint256 balance = _outputs[i].balance;
        require(isFlushable(i), "Output ammount is not above output threshold");
        _outputs[i].balance = 0;
        bool success = transfer(_outputs[i].output, balance);
        require(success, "Failed to transfer the funds, aborting.");
        _liquidated = _liquidated.sub(balance);
        emit PaymentSent(_outputs[i].output, balance);
    }

    function addOutput(
        address payable output,
        uint256 split,
        uint256 threshold
    ) public onlyAuthorizedChanger() {
        _addOutput(output, split, threshold);
    }

    function _addOutput(
        address payable output,
        uint256 split,
        uint256 threshold
    ) internal {
        _outputs.push(Output({output: output, split: split, threshold: threshold, balance: 0}));
        _splitTotal = _splitTotal.add(split);
    }

    function removeOutput(uint256 idx) public onlyAuthorizedChanger() {
        require(idx < _outputs.length, "Invalid index");
        uint256 balance = _outputs[idx].balance;
        if (balance > 0) {
            _outputs[idx].balance = 0;
            bool success = transfer(_outputs[idx].output, balance);
            require(success, "Failed to transfer the funds, aborting.");
            _liquidated = _liquidated.sub(balance);
        }
        _splitTotal = _splitTotal.sub(_outputs[idx].split);
        _outputs[idx] = _outputs[_outputs.length - 1];
        _outputs.pop();
    }

    function setThreshold(uint256 threshold) public onlyAuthorizedChanger() {
        _threshold = threshold;
    }

    function getThreshold() public view returns (uint256) {
        return _threshold;
    }

    function getSplit() public view returns (uint256) {
        return _splitTotal;
    }

    function getLiquidated() public view returns (uint256) {
        return _liquidated;
    }

    function getNumOutputs() public view returns (uint256) {
        return _outputs.length;
    }

    function isFlushable(uint256 i) public view returns (bool) {
        return _outputs[i].balance > _outputs[i].threshold;
    }

    function isLiquidable() public view returns (bool) {
        uint256 balance = getBalance();
        uint256 toLiquidate = getLiquidated();
        uint256 amount = balance.sub(toLiquidate);
        return amount > _threshold;
    }

    function getOutput(uint256 idx)
        public
        view
        returns (
            address,
            uint256,
            uint256,
            uint256
        )
    {
        return (
            _outputs[idx].output,
            _outputs[idx].split,
            _outputs[idx].balance,
            _outputs[idx].threshold
        );
    }

    function getToken() public view virtual returns (address);

    function getAll()
        public
        view
        virtual
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            address,
            uint256
        );

    receive() external payable {}
}
