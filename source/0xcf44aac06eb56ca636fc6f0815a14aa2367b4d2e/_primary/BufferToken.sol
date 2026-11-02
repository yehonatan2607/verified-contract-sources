/*
Copyright MOC Investments Corp. 2020. All rights reserved.
 
You acknowledge and agree that MOC Investments Corp. (“MOC”) (or MOC’s licensors) own all legal right, title and
interest in and to the work, software, application, source code, documentation and any other documents in this
repository (collectively, the “Program”), including any intellectual property rights which subsist in the
Program (whether those rights happen to be registered or not, and wherever in the world those rights may exist),
whether in source code or any other form.
 
Subject to the limited license below, you may not (and you may not permit anyone else to) distribute, publish, copy,
modify, merge, combine with another program, create derivative works of, reverse engineer, decompile or otherwise
attempt to extract the source code of, the Program or any part thereof, except that you may contribute to
this repository.
 
You are granted a non-exclusive, non-transferable, non-sublicensable license to distribute, publish, copy, modify,
merge, combine with another program or create derivative works of the Program (such resulting program, collectively,
the “Resulting Program”) solely for Non-Commercial Use as long as you:
 1. give prominent notice (“Notice”) with each copy of the Resulting Program that the Program is used in the Resulting
  Program and that the Program is the copyright of MOC Investments Corp.; and
 2. subject the Resulting Program and any distribution, publication, copy, modification, merger therewith,
  combination with another program or derivative works thereof to the same Notice requirement and Non-Commercial
  Use restriction set forth herein.
 
“Non-Commercial Use” means each use as described in clauses (1)-(3) below, as reasonably determined by MOC Investments
Corp. in its sole discretion:
 1. personal use for research, personal study, private entertainment, hobby projects or amateur pursuits, in each
 case without any anticipated commercial application;
 2. use by any charitable organization, educational institution, public research organization, public safety or health
 organization, environmental protection organization or government institution; or
 3. the number of monthly active users of the Resulting Program across all versions thereof and platforms globally
 do not exceed 10,000 at any time.
 
You will not use any trade mark, service mark, trade name, logo of MOC Investments Corp. or any other company or
organization in a way that is likely or intended to cause confusion about the owner or authorized user of such marks,
names or logos.
 
If you have any questions, comments or interest in pursuing any other use cases, please reach out to us
at moc.license@moneyonchain.com.

*/

pragma solidity 0.6.12;


/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}


/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}



/**
  @title ChangeContract
  @notice This interface is the one used by the governance system.
  @dev If you plan to do some changes to a system governed by this project you should write a contract
  that does those changes, like a recipe. This contract MUST not have ANY kind of public or external function
  that modifies the state of this ChangeContract, otherwise you could run into front-running issues when the governance
  system is fully in place.
 */
interface ChangeContract {
    /**
      @notice Override this function with a recipe of the changes to be done when this ChangeContract
      is executed
     */
    function execute() external;
}


/**
  @title Governor
  @notice Governor interface. This functions should be overwritten to
  enable the comunnication with the rest of the system
  */
interface IGovernor {
    /**
      @notice Function to be called to make the changes in changeContract
      @dev This function should be protected somehow to only execute changes that
      benefit the system. This decision process is independent of this architechture
      therefore is independent of this interface too
      @param changeContract Address of the contract that will execute the changes
     */
    function executeChange(ChangeContract changeContract) external;

    /**
      @notice Function to be called to make the changes in changeContract
      @param _changer Address of the contract that will execute the changes
     */
    function isAuthorizedChanger(address _changer) external view returns (bool);
}




/**
 * @title Initializable
 *
 * @dev Helper contract to support initializer functions. To use it, replace
 * the constructor with a function that has the `initializer` modifier.
 * WARNING: Unlike constructors, initializer functions must be manually
 * invoked. This applies both to deploying an Initializable contract, as well
 * as extending an Initializable contract via inheritance.
 * WARNING: When used with inheritance, manual care must be taken to not invoke
 * a parent initializer twice, or ensure that all initializers are idempotent,
 * because this is not dealt with automatically as with constructors.
 */
contract Initializable {

  /**
   * @dev Indicates that the contract has been initialized.
   */
  bool private initialized;

  /**
   * @dev Indicates that the contract is in the process of being initialized.
   */
  bool private initializing;

  /**
   * @dev Modifier to use in the initializer function of a contract.
   */
  modifier initializer() {
    require(initializing || isConstructor() || !initialized, "Contract instance has already been initialized");

    bool isTopLevelCall = !initializing;
    if (isTopLevelCall) {
      initializing = true;
      initialized = true;
    }

    _;

    if (isTopLevelCall) {
      initializing = false;
    }
  }

  /// @dev Returns true if and only if the function is running in the constructor
  function isConstructor() private view returns (bool) {
    // extcodesize checks the size of the code stored in an address, and
    // address returns the current address. Since the code is still not
    // deployed when running a constructor, any checks on its code size will
    // yield zero, making it an effective way to detect if a contract is
    // under construction or not.
    address self = address(this);
    uint256 cs;
    assembly { cs := extcodesize(self) }
    return cs == 0;
  }

  // Reserved storage space to allow for layout changes in the future.
  uint256[50] private ______gap;
}



/**
  @title Governed
  @notice Base contract to be inherited by governed contracts
  @dev This contract is not usable on its own since it does not have any _productive useful_ behaviour
  The only purpose of this contract is to define some useful modifiers and functions to be used on the
  governance aspect of the child contract
  */
contract Governed {
    /**
      @notice The address of the contract which governs this one
     */
    IGovernor public governor;

    string private constant NOT_AUTHORIZED_CHANGER = "not_authorized_changer";

    /**
      @notice Modifier that protects the function
      @dev You should use this modifier in any function that should be called through
      the governance system
     */
    modifier onlyAuthorizedChanger() {
        require(governor.isAuthorizedChanger(msg.sender), NOT_AUTHORIZED_CHANGER);
        _;
    }

    /**
      @notice Initialize the contract with the basic settings
      @dev This initialize replaces the constructor but it is not called automatically.
      It is necessary because of the upgradeability of the contracts
      @param _governor Governor address
     */
    function _initialize(IGovernor _governor) internal {
        governor = _governor;
    }

    /**
      @notice Change the contract's governor. Should be called through the old governance system
      @param newIGovernor New governor address
     */
    function changeIGovernor(IGovernor newIGovernor) external onlyAuthorizedChanger {
        governor = newIGovernor;
    }

    /**
      @notice This method is used by a change contract to access the storage freely even without a setter.
      @param data the serialized function arguments
     */
    function delegateCallToChanger(bytes calldata data)
        external
        onlyAuthorizedChanger
        returns (bytes memory)
    {
        address changerContrat = msg.sender;
        (bool success, bytes memory result) = changerContrat.delegatecall(
            abi.encodeWithSignature("impersonate(bytes)", data)
        );
        require(success, "Error in delegate call");
        return result;
    }

    // Leave a gap betweeen inherited contracts variables in order to be
    // able to add more variables in them later
    uint256[50] private upgradeGap;
}


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


contract BufferToken is BufferBase {
    using SafeMath for uint256;

    IERC20 internal _token;

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

