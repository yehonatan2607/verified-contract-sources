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


interface IRegistry {
    // *** Getter Methods ***
    function getDecimal(bytes32 _key) external view returns (int232 base, int16 exp);

    function getUint(bytes32 _key) external view returns (uint248);

    function getString(bytes32 _key) external view returns (string memory);

    function getAddress(bytes32 _key) external view returns (address);

    function getBytes(bytes32 _key) external view returns (bytes memory);

    function getBool(bytes32 _key) external view returns (bool);

    function getInt(bytes32 _key) external view returns (int248);

    // *** Setter Methods ***
    function setDecimal(
        bytes32 _key,
        int232 _base,
        int16 _exp
    ) external;

    function setUint(bytes32 _key, uint248 _value) external;

    function setString(bytes32 _key, string calldata _value) external;

    function setAddress(bytes32 _key, address _value) external;

    function setBytes(bytes32 _key, bytes calldata _value) external;

    function setBool(bytes32 _key, bool _value) external;

    function setInt(bytes32 _key, int248 _value) external;

    // *** Delete Methods ***
    function deleteDecimal(bytes32 _key) external;

    function deleteUint(bytes32 _key) external;

    function deleteString(bytes32 _key) external;

    function deleteAddress(bytes32 _key) external;

    function deleteBytes(bytes32 _key) external;

    function deleteBool(bytes32 _key) external;

    function deleteInt(bytes32 _key) external;

    // Nov 2020 Upgrade
    // *** Getter Methods ***
    function getAddressArrayLength(bytes32 _key) external view returns (uint256);

    function getAddressArrayElementAt(bytes32 _key, uint256 idx) external view returns (address);

    function pushAddressArrayElement(bytes32 _key, address _addr) external;

    function getAddressArray(bytes32 _key) external view returns (address[] memory);

    function addressArrayContains(bytes32 _key, address value) external view returns (bool);

    // *** Setters ***
    function pushAddressArray(bytes32 _key, address[] memory data) external;

    function clearAddressArray(bytes32 _key) external;

    function removeAddressArrayElement(bytes32 _key, address value) external;
}

// prettier-ignore


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

// prettier-ignore


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



interface IVestingMachine {
    /// @notice Retrieve vesting parameters
    function getParameters() external view returns (uint256[] memory, uint256[] memory);

    /// @notice Mark contract as verified by holder
    function verify() external;

    /// @notice Returns current holder address
    function getHolder() external view returns (address);

    /// @notice Calls a function from target passing data
    /// @param target Target contract to call (must be one of: staking, vesting or voting machine)
    /// @param data Data to pass target contract
    function callWithData(address target, bytes memory data) external;

    /// @notice approve a transfer to the staking machine.
    /// @param amount Token amount to approve
    function approve(uint256 amount) external;

    /// @notice deposit MOCs in the staking machine
    /// @param amount Token amount to approve
    function deposit(uint256 amount) external;

    /// @notice Withdraws tokens to holder address
    /// @param amount Tokens amount to withdraw
    /// @return Returns true on success
    function withdraw(uint256 amount) external returns (bool);

    /// @notice Withdraws all available tokens to holder address
    /// @return Returns true on success
    function withdrawAll() external returns (bool);

    /// @notice Minimum token amount required to be locked
    /// @param timestamp date to check
    function getLockedAt(uint256 timestamp) external view returns (uint256);

    /// @notice Minimum token amount required to be locked
    function getLocked() external view returns (uint256);

    /// @notice Token amount available for withdrawal
    function getAvailable() external view returns (uint256);

    /// @notice Returns true after contract has been verified by holder
    function isVerified() external view returns (bool);

    /// @notice Total token balance configured
    function getTotal() external view returns (uint256);

    /// @notice Update vesting parameters (only can be called by factory)
    /// @param _percentages array of token percentages locked at a date
    /// @param _timedeltas array of date deltas from TGE when percentages are valid
    // function update(uint256[] memory _percentages, uint256[] memory _timedeltas) external;

    /// @notice Change holder address
    /// @param newHolder the new holder (only can be called by governance)
    function setHolder(address newHolder) external;

    /// @notice Configure vesting total balance (only can be called by factory)
    function setTotal(uint256 amount) external;
}


interface IVestingFactory {
    /// @notice Create a holder wallet
    /// @param holder wallet's owner
    /// @param percentages percentages allowed in each step
    /// @param timedeltas duration of each step
    function create(
        address holder,
        uint256[] memory percentages,
        uint256[] memory timedeltas
    ) external;

    /// @notice Update the vesting machine values
    /// function update(
    ///     IVestingMachine wallet,
    ///     uint256[] memory percentages,
    ///     uint256[] memory timedeltas
    /// ) external;

    /// @notice Set the TGE time enabling holder wallets
    function setTGE() external;

    /// @notice Returns true when the TGE was configured
    function isTGEConfigured() external view returns (bool);

    /// @notice Returns the configured TGE timestamp
    function getTGETimestamp() external view returns (uint256);

    /// @notice Set a holder wallet balance
    /// @param wallet the vesting machine
    /// @param amount wallet balance
    function setTotal(IVestingMachine wallet, uint256 amount) external;

    /// @notice Return registry
    function getRegistry() external view returns (IRegistry);

    /// @notice Get the length of the list of vesting machines
    function getVestingMachinesLen() external view returns (uint256);

    /// @notice Get the an entry of the list of vesting machines
    /// @param idx the index in the list
    function getVestingMachinesEntry(uint256 idx) external view returns (address);
}


// prettier-ignore



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


/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
contract ContextUpgradeSafe is Initializable {
    // Empty internal constructor, to prevent people from mistakenly deploying
    // an instance of this contract, which should be used via inheritance.

    function __Context_init() internal initializer {
        __Context_init_unchained();
    }

    function __Context_init_unchained() internal initializer {


    }


    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }

    uint256[50] private __gap;
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
contract OwnableUpgradeSafe is Initializable, ContextUpgradeSafe {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */

    function __Ownable_init() internal initializer {
        __Context_init_unchained();
        __Ownable_init_unchained();
    }

    function __Ownable_init_unchained() internal initializer {


        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);

    }


    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    uint256[49] private __gap;
}

// prettier-ignore


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





/// @title This contract provides an interface for feeding prices from oracles, and
///        get the current price. One contract must be instanced per supported coin pair,
///        and registered through OracleManager global contract.
/// This contract has two lists:
/// 1) A subscribed list (EnumerableSet.AddressSet) oracles owner addresses, this list has a max size (30).
/// 2) A selected list, EnumerableSet.AddressSet of oracles owner addresses that are selected to participate in
/// current publication round (10 entries max size).
///
/// Oracles are subscribed by adding them to the subscribed oracle list. When the list is full
/// the oracle with less stake can be removed by a new oracle that is trying to
/// subscribe (if its stake is greater than his).
/// On each round switch the list of selected oracles is populated with the 10 Oracles with more stake. An oracle
/// can unsubscribe itself from the subscribed list in the middle of the round, in this case, the oracle is still
/// listed in the selected list until the round ends.
/// If an oracle withdraw some stake then his participation in the round is put into consideration: If the
/// oracle ends up having less stake than the next oracle in the subscribed list (but not in the selected list) then
/// it is removed from the selected list and the point he accumulated during the round are lost (set to zero).

interface ICoinPairPrice {
    // getOracleOwnerAddress: Given an Oracle address return the Oracle Owner address.
    // Used during publication, the servers sign with the oracle address, but the list of selected oracles
    // is by oracle owner address.
    // getOracleOwnerStake: Get the stake stored in the supporters smart-contract
    // prettier-ignore
    struct CoinPairPriceCallbacks {
        function (address) external view returns (address) getOracleOwnerAddress;
        function (address) external view returns (uint256) getOracleOwnerStake;
    }

    /// @notice subscribe an oracle to this coin pair, allowing it to be selected in the next round.
    /// If the subscribed list is full and the current oracle has more stake than one with minimum stake in the
    /// subscribed list, then the one with minimum stake is replaced.
    /// @param oracleOwnerAddr The address of the owner of the oracle to remove from system.
    /// @dev This is designed to be called from OracleManager.
    function subscribe(address oracleOwnerAddr) external;

    /// @notice Unsubscribe an oracle from this coin pair. The oracle won't be selected in the next round.
    /// After the round end, the oracle can withdraw stake without having the risk of loosing won points.
    /// @param oracleOwnerAddr The address of the owner of the oracle to remove from system.
    /// @dev This is designed to be called from OracleManager.
    function unsubscribe(address oracleOwnerAddr) external;

    /// @notice Returns true if an oracle is subscribed to this contract' coin pair
    /// @param oracleOwnerAddr The address of the owner of the oracle to remove from system.
    /// @dev This is designed to be called from OracleManager.
    function isSubscribed(address oracleOwnerAddr) external view returns (bool);

    /// @notice Publish a price. (The message contain oracleAddresses that must be converted to owner addresses).
    /// @param _version Version number of message format (3)
    /// @param _coinpair The coin pair to report (must match this contract)
    /// @param _price Price to report.
    /// @param _votedOracle The address of the oracle voted as a publisher by the network.
    /// @param _blockNumber The block number acting as nonce to prevent replay attacks.
    /// @param _sigV The array of V-component of Oracle signatures.
    /// @param _sigR The array of R-component of Oracle signatures.
    /// @param _sigS The array of S-component of Oracle signatures.
    function publishPrice(
        uint256 _version,
        bytes32 _coinpair,
        uint256 _price,
        address _votedOracle,
        uint256 _blockNumber,
        uint8[] calldata _sigV,
        bytes32[] calldata _sigR,
        bytes32[] calldata _sigS
    ) external;

    /// @notice Publish a price without signature validation (when there is an emergecy!!!).
    /// @param _price Price to report.
    function emergencyPublish(uint256 _price) external;

    /// @notice The oracle owner has withdrawn some stake.
    /// Must check if the oracle is part of current round and if he lost his place with the
    /// new stake value (the stake is global and is saved in the supporters contract).
    /// @param oracleOwnerAddr the oracle owner that is trying to withdraw
    function onWithdraw(address oracleOwnerAddr) external returns (uint256);

    /// @notice Switch contract context to a new round. With the objective of
    /// being a decentralized solution, this can be called by *anyone* if current
    /// round lock period is expired.
    /// This method search the subscribed list and choose the 10 with more stake.
    function switchRound() external;

    //////////////////////////////////////////////////////////////////////////////////// GETTERS

    /// @notice Return the available reward fees
    ///
    function getAvailableRewardFees() external view returns (uint256);

    //////////////////////////////////////////////////////////////////////////////////// GETTERS TO GET CURRENT PRICE
    // MUST BE WHITELISTED
    /// @notice Return the current price, compatible with old MOC Oracle
    function peek() external view returns (bytes32, bool);

    /// @notice Return the current price
    function getPrice() external view returns (uint256);

    ///////////////////////////////////////////////////////////////////////////////// GETTERS TO GET CURRENT PRICE END

    /// @notice Return current round information
    function getRoundInfo()
        external
        view
        returns (
            uint256 round,
            uint256 startBlock,
            uint256 lockPeriodTimestamp,
            uint256 totalPoints,
            address[] memory selectedOwners,
            address[] memory selectedOracles
        );

    /// @notice Return round information for specific oracle
    function getOracleRoundInfo(address addr)
        external
        view
        returns (uint256 points, bool selectedInCurrentRound);

    // The maximum count of oracles selected to participate each round
    function maxOraclesPerRound() external view returns (uint256);

    // The round lock period in secs
    function roundLockPeriodSecs() external view returns (uint256);

    function isOracleInCurrentRound(address oracleAddr) external view returns (bool);

    /// @notice Returns the amount of oracles subscribed to this coin pair.
    function getSubscribedOraclesLen() external view returns (uint256);

    /// @notice Returns the oracle owner address that is subscribed to this coin pair
    /// @param idx index to query.
    function getSubscribedOracleAtIndex(uint256 idx) external view returns (address ownerAddr);

    // Public variable
    function getMaxSubscribedOraclesPerRound() external view returns (uint256);

    // Public variable
    function getCoinPair() external view returns (bytes32);

    // Public variable
    function getLastPublicationBlock() external view returns (uint256);

    // Public variable
    function getValidPricePeriodInBlocks() external view returns (uint256);

    // Public variable
    function getEmergencyPublishingPeriodInBlocks() external view returns (uint256);

    // Public variable
    function getOracleManager() external view returns (IOracleManager);

    // Public variable
    function getToken() external view returns (IERC20);

    function getRegistry() external view returns (IRegistry);

    // Public value from Registry:
    //   The minimum count of oracles selected to participate each round
    function getMinOraclesPerRound() external view returns (uint256);
}


/// This contract manages the Oracle and CoinPair registration info.
/// The Oracle python server interacts with this contract:
/// - Coin pair registration
/// - Oracle registration to coin pairs
/// - Access Oracle info (oracle address + url) indexed by oracle owner address
/// - Get the oracle information (url + the specifics of some coin pair rounds) from an oracle address
/// - Get the oracle address from the owner address.
interface IOracleManager {
    // getOracleOwnerStake: Get the stake stored in the supporters smart-contract
    // prettier-ignore
    struct OracleManagerCallbacks {
        function (address) external view returns (uint256) getOracleOwnerStake;
    }

    /// @notice Register a new coin pair contract (the contract must be created separately).
    /// Once created the coin pairs cannot be removed.
    /// @param coinPair The bytes32-encoded coinpair string (e.g. BTCUSD)
    /// @param addr The contract address associated to the coin pair.
    function registerCoinPair(bytes32 coinPair, address addr) external;

    /// Register an oracle in the system must be called by the oracle owner.
    /// @notice Registers the oracle and transfer the specified caller's MOC token stake.
    /// @param oracleOwnerAddr The address of the owner of the oracle.
    /// @param oracleAddr Address of the Oracle to register.
    /// @param internetName Public Internet name of this Oracle.
    function registerOracle(
        address oracleOwnerAddr,
        address oracleAddr,
        string calldata internetName
    ) external;

    /// @notice Change the oracle "internet" name (URI), called by the owner.
    /// @param oracleOwnerAddr The address of the owner of the oracle.
    /// @param name The new name to set.
    function setOracleName(address oracleOwnerAddr, string calldata name) external;

    /// @notice Change the oracle address, called by the owner.
    /// @param oracleOwnerAddr The address of the owner of the oracle.
    /// @param oracleAddr new value for the address of the oracle
    function setOracleAddress(address oracleOwnerAddr, address oracleAddr) external;

    /// @notice Removes the oracle registration info. Must be called by the owner
    /// The oracle must be previously unregistered from all coin pairs.
    /// @param oracleOwnerAddr The address of the owner of the oracle to remove from system.
    function removeOracle(address oracleOwnerAddr) external;

    /// @notice Subscribe a registered oracle to participate in the next round of a registered coin-pair.
    /// @param oracleOwnerAddr Address of oracle owner
    function subscribeToCoinPair(address oracleOwnerAddr, bytes32 coinPair) external;

    /// @notice Unsubscribe a registered oracle from participating in rounds of a registered coin-pair.
    /// The oracle is flagged so it is not selected in the next round.
    /// @param oracleOwnerAddr Address of oracle owner
    function unSubscribeFromCoinPair(address oracleOwnerAddr, bytes32 coinPair) external;

    /// @notice The oracle owner did a partial withdrawal of funds
    /// 1. The oracle address is searched by the owner address.
    /// 2. Each coin pair to which the oracle is subscribed is consulted to:
    ///   - Check if the new amount is enough to stay in the current round.
    ///       If not the oracle is replaced and lost his points.
    ///   - Get the timestamp for the round end.
    /// The return value is the maximum timestamp from all the coin pairs.
    /// @param oracleOwnerAddr Address of oracle owner
    /// @return the timestamp until which the funds must be locked.
    function onWithdraw(address oracleOwnerAddr) external returns (uint256);

    //////////////////////////////////////////////////////////////////////////////////// GETTERS USED BY COINPAIR
    /// @notice Used by the coin pair to get the oracle address from the oracleOwnerAddress.
    /// @param  oracleOwnerAddr the address of the owner of the oracle.
    /// @return oracleAddr Address of oracle
    function getOracleAddress(address oracleOwnerAddr) external view returns (address oracleAddr);

    /// @notice Returns true if oracle is registered.
    /// @param ownerAddr The address of the oracle's owner.
    function isRegistered(address ownerAddr) external view returns (bool);

    /// @notice Used by CoinPair
    /// @param oracleAddr The oracle address not the owner address.
    function getOracleOwner(address oracleAddr) external view returns (address);

    /// @notice Returns the amount of owners registered.
    function getRegisteredOraclesLen() external view returns (uint256);

    /// @notice Returns the oracle name and address at index.
    /// @param idx index to query.
    function getRegisteredOracleAtIndex(uint256 idx)
        external
        view
        returns (
            address ownerAddr,
            address oracleAddr,
            string memory url
        );

    //////////////////////////////////////////////////////////////////////////////////// GETTERS USED BY COINPAIR END

    //////////////////////////////////////////////////////////////////////////////////// GETTERS

    // TODO: Check what is the minimum amount of getters the python server needs.

    /// @notice Returns true if an oracle is subscribed to a coin pair
    function isSubscribed(address oracleAddr, bytes32 coinPair) external view returns (bool);

    /// @notice Return true if the oracle is registered on this coin-pair
    /// @param oracleAddr addr The address of the Oracle check for.
    function isOracleRegistered(address oracleAddr) external view returns (bool);

    /// @notice Returns registration information for a registered Oracle.
    /// @param oracleAddr addr The address of the Oracle to query for.
    function getOracleRegistrationInfo(address oracleAddr)
        external
        view
        returns (
            string memory internetName,
            uint256 stake,
            address _owner
        );

    /// @notice Returns round information for a registered oracle in a specific coin-pair.
    /// @param oracleAddr address of the oracle to query for.
    /// @param coinpair The coin pair to lookup.
    function getOracleRoundInfo(address oracleAddr, bytes32 coinpair)
        external
        view
        returns (uint256 points, bool selectedInCurrentRound);

    /// @notice Returns true if an oracle satisfies conditions to be removed from system.
    /// @param oracleAddr the oracle address to lookup.
    function canRemoveOracle(address oracleAddr) external view returns (bool);

    /// @notice Get the stake in MOCs that an oracle has.
    /// @param oracleAddr The address of the oracle.
    function getStake(address oracleAddr) external view returns (uint256 balance);

    //////////////////////////////////////////////////////////////////////////////////// GETTER TO LIST COIN PAIRS

    /// @notice Returns the count of registered coin pairs.
    /// Keep in mind that Deleted coin-pairs will contain zeroed addresses.
    function getCoinPairCount() external view returns (uint256);

    /// @notice Returns the coin pair at index.
    /// @param i index to query.
    function getCoinPairAtIndex(uint256 i) external view returns (bytes32);

    /// @notice Return the contract address for a specified registered coin pair.
    /// @param coinpair Coin-pair string to lookup (e.g: BTCUSD)
    /// @return address Address of contract or zero if does not exist or was deleted.
    function getContractAddress(bytes32 coinpair) external view returns (address);

    /// @notice Searches a coinpair in coinPairList
    /// @param coinPair The bytes32-encoded coinpair string (e.g. BTCUSD)
    /// @param hint Optional hint to start traversing the coinPairList array, zero is to search all the array.
    function getCoinPairIndex(bytes32 coinPair, uint256 hint) external view returns (uint256);

    function getMaxStake(address[] calldata addresses) external view returns (address, uint256);

    //////////////////////////////////////////////////////////////////////////////////// GETTER TO LIST COIN PAIRS END

    // Public variable
    function getStakingContract() external view returns (IStakingMachine);

    // Public variable
    function getMinCPSubscriptionStake() external view returns (uint256);
}



interface IDelayMachine {
    /// @notice Accept a deposit from an account.
    /// @param mocs token quantity
    /// @param expiration the expiration date for this deposit
    /// @return id the transaction id
    function deposit(
        uint256 mocs,
        address destination,
        uint256 expiration
    ) external returns (uint256 id);

    /// @notice Cancel a transaction returning the funds to the source
    /// @param id transaction id
    function cancel(uint256 id) external;

    /// @notice Withdraw stake, send it to the delay machine.
    /// @param id transaction id
    function withdraw(uint256 id) external;

    /// @notice Returns the list of transaction for some account
    /// @return ids transaction ids
    /// @return amounts token quantity
    /// @return expirations expiration dates
    function getTransactions(address account)
        external
        view
        returns (
            uint256[] memory ids,
            uint256[] memory amounts,
            uint256[] memory expirations
        );

    /// @notice Returns the total balance in MOCs for an account
    function getBalance(address account) external view returns (uint256);

    // Public variable
    function getToken() external view returns (IERC20);

    // Public variable
    function getLastId() external view returns (uint256);

    // Public variable
    function getSource() external view returns (address);
}


interface IStakingMachine {
    /// @notice Used by the voting machine to lock the current balance of MOCs.
    /// @param mocHolder the moc holder whose mocs will be locked.
    /// @param untilTimestamp timestamp until which the mocs will be locked.
    function lockMocs(address mocHolder, uint256 untilTimestamp) external;

    /// @notice Accept a deposit from an account.
    /// Delegate to the Supporters smart contract.
    /// @param mocs token quantity
    /// @param destination the destination account of this deposit.
    function deposit(uint256 mocs, address destination) external;

    /// @notice Accept a deposit from an account.
    /// @param mocs token quantity
    /// @param destination the destination account of this deposit.
    /// @param source the address that approved the transfer
    function depositFrom(
        uint256 mocs,
        address destination,
        address source
    ) external;

    /// @notice Withdraw stake, send it to the delay machine.
    /// @param mocs token quantity
    function withdraw(uint256 mocs) external;

    /// @notice Reports the balance of MOCs for a specific user.
    /// @param user user address
    function getBalance(address user) external view returns (uint256);

    /// @notice Reports the locked balance of MOCs for a specific user.
    /// @param user user address
    function getLockedBalance(address user) external view returns (uint256);

    /// @notice Reports the balance of locked MOCs for a specific user.
    /// Delegates to the Supporters smart contract.
    /// @param user user address
    /// @return amount the amount of mocs locked
    /// @return untilTimestamp the timestamp that corresponds to the locking date.
    function getLockingInfo(address user)
        external
        view
        returns (uint256 amount, uint256 untilTimestamp);

    // Public variable
    function getSupporters() external view returns (address);

    // Public variable
    function getOracleManager() external view returns (IOracleManager);

    // Public variable
    function getMocToken() external view returns (IERC20);

    // Public variable
    function getDelayMachine() external view returns (IDelayMachine);

    // Public variable
    function getWithdrawLockTime() external view returns (uint256);
}

interface IStakingMachineOracles {
    /// @notice Register an oracle
    /// @param oracleAddr address of the oracle (from which we publish prices)
    /// @param url url used by the oracle server
    function registerOracle(address oracleAddr, string calldata url) external;

    /// @notice Change the oracle "internet" name (URI)
    /// @param url The new url to set.
    function setOracleName(string calldata url) external;

    /// @notice Change the oracle address
    /// @param oracleAddr The new oracle address
    function setOracleAddress(address oracleAddr) external;

    /// @notice Return true if the oracle is registered.
    /// @param oracleAddr addr The address of the Oracle check for.
    function isOracleRegistered(address oracleAddr) external view returns (bool);

    /// @notice Returns true if an oracle satisfies conditions to be removed from system.
    /// @param oracleAddr the oracle address to lookup.
    function canRemoveOracle(address oracleAddr) external view returns (bool);

    /// @notice Remove an oracle.
    function removeOracle() external;

    /// @notice Returns the count of registered coin pairs.
    /// Keep in mind that Deleted coin-pairs will contain zeroed addresses.
    function getCoinPairCount() external view returns (uint256);

    /// @notice Returns the coin pair at index.
    /// @param i index to query.
    function getCoinPairAtIndex(uint256 i) external view returns (bytes32);

    /// @notice Return the contract address for a specified registered coin pair.
    /// @param coinpair Coin-pair string to lookup (e.g: BTCUSD)
    /// @return address Address of contract or zero if does not exist or was deleted.
    function getContractAddress(bytes32 coinpair) external view returns (address);

    /// @notice Searches a coinpair in coinPairList
    /// @param coinPair The bytes32-encoded coinpair string (e.g. BTCUSD)
    /// @param hint Optional hint to start traversing the coinPairList array, zero is to search all the array.
    function getCoinPairIndex(bytes32 coinPair, uint256 hint) external view returns (uint256);

    /// @notice Subscribe an oracle to a coin pair.
    /// @param coinPair coin pair to subscribe, for example BTCUSD
    function subscribeToCoinPair(bytes32 coinPair) external;

    /// @notice Unsubscribe an oracle from a coin pair.
    /// @param coinPair coin pair to unsubscribe, for example BTCUSD
    function unSubscribeFromCoinPair(bytes32 coinPair) external;

    /// @notice Returns true if an oracle is subscribed to a coin pair
    /// @param oracleAddr address of the oracle
    /// @param coinPair coin pair to unsubscribe, for example BTCUSD
    function isSubscribed(address oracleAddr, bytes32 coinPair) external view returns (bool);

    /// @notice Returns the amount of owners registered.
    /// Delegates to the Oracle Manager smart contract.
    function getRegisteredOraclesLen() external view returns (uint256);

    /// @notice Returns the oracle name and address at index.
    /// Delegates to the Oracle Manager smart contract.
    /// @param idx index to query.
    function getRegisteredOracleAtIndex(uint256 idx)
        external
        view
        returns (
            address ownerAddr,
            address oracleAddr,
            string memory url
        );
}


interface IVotingMachine {
    /**
        get current contract state
        */
    function getState() external view returns (uint256);

    /**
        return the current voting round
        */
    function getVotingRound() external view returns (uint256);

    /**
    Pre Vote a proposal

    @param _proposal Address of the change contract that will be executed if this vote is successful
    */
    function preVote(address _proposal) external;

    /**
    Vote a proposal

    @param _inFavorAgainst Type of vote
    */
    function vote(bool _inFavorAgainst) external;

    /**
    There is a veto Condition

    */
    function vetoCondition() external;

    /**
    Veto
    */
    function veto() external;

    function readyToPreVoteStep() external view returns (bool);

    /**
    preVoteStep
    */
    function preVoteStep() external;

    function readyToVoteStep() external view returns (bool);

    /**
    voteStep
    */
    function voteStep() external;

    /**
    vetoStep
    */
    function vetoStep() external;

    /**
    acceptedStep
    */
    function acceptedStep() external;

    /**
    Get the pre-voting registered proposal count.
    */
    function getProposalCount() external view returns (uint256);

    /**
    Get pre-voting proposal address and information by index

    @param _index Index of proposal to query.
    */
    function getProposalByIndex(uint256 _index)
        external
        view
        returns (
            address proposalAddress,
            uint256 proposalVotingRound,
            uint256 proposalVotes,
            uint256 proposalExpirationTimeStamp
        );

    /**
    Get voting data
    */
    function getVotingData()
        external
        view
        returns (
            address winnerProposal,
            uint256 inFavorVotes,
            uint256 againstVotes,
            uint256 votingExpirationTime
        );

    /**
        Get user vote
    */
    function getUserVote(address user)
        external
        view
        returns (address voteAddress, uint256 voteRound);

    /**
    will the call to unregister be successfull?

    @param _proposal Address of the change contract that will be executed if this vote is successful
    */
    function canUnregister(address _proposal) external view returns (bool);

    /**
    Unregister a proposal, free the assets it uses.

    @param _proposal Address of the change contract that will be executed if this vote is successful
    */
    function unregister(address _proposal) external;
}




/**
  @notice Based on heavily on EnumberableSet, but with the ability to clear all the contents.
 */
library AddressSetLib {
    using SafeMath for uint256;

    struct AddressSet {
        // Storage of set values
        address[] _values;
        // Position of the value in the `values` array, plus 1 because index 0
        // means a value is not in the set.
        mapping(address => uint256) _indexes;
    }

    function init() internal pure returns (AddressSet memory) {
        return AddressSet({_values: new address[](0)});
    }

    /**
     * @dev Removes all value from a set. O(N).
     *
     */
    function clear(AddressSet storage set) internal {
        for (uint256 i = 0; i < set._values.length; i++) {
            delete set._indexes[set._values[i]];
        }
        delete set._values;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        // We read and store the value's index to prevent multiple reads from the same storage slot
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            // When the value to delete is the last one, the swap operation is unnecessary. However, since this occurs
            // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

            address lastvalue = set._values[lastIndex];

            // Move the last value to the index where the value to delete is
            set._values[toDeleteIndex] = lastvalue;
            // Update the index for the moved value
            set._indexes[lastvalue] = toDeleteIndex + 1;
            // All indexes are 1-based

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the index for the deleted slot
            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        require(set._values.length > index, "index out of bounds");
        return set._values[index];
    }

    /**
     * @dev Returns the set contents as an array
     */
    function asArray(AddressSet storage set)
        internal
        view
        returns (address[] memory selectedOracles)
    {
        return set._values;
    }
}

// Autogenerated by registryConstants.js
// solhint-disable func-name-mixedcase

contract RegistryConstants {
    // MOC_PROJECT_VERSION = keccak256(moc.project.version)
    bytes32 public constant MOC_PROJECT_VERSION =
        0xc1c87e0508bb8270ee6a6dbe630baa072e6e3d5968981666724b9333430e1c31;

    // MOC_TOKEN = keccak256(moc.token)
    bytes32 public constant MOC_TOKEN =
        0x4bd5e7ff929fdd1ba62a33f76e0f40e97bb35e8bf126c0d9d91ce5c69a4bc521;

    // MOC_DELAY_MACHINE = keccak256(moc.delay-machine)
    bytes32 public constant MOC_DELAY_MACHINE =
        0x66b60892ff6e7f0da16db27046f5960fdfd6bce5c3c8c21d56ccca3236a6281b;

    // MOC_STAKING_MACHINE = keccak256(moc.staking-machine)
    bytes32 public constant MOC_STAKING_MACHINE =
        0x3c557531fea67120f21bc7711270a96f1b8cff3dfe3dd798a8a9f09ce9b77972;

    // MOC_VESTING_MACHINE = keccak256(moc.vesting-machine)
    bytes32 public constant MOC_VESTING_MACHINE =
        0x7dfea4fb968e2599cdb7b3028c07d0188d0f92d1d00bd95c2805523c224649dd;

    // MOC_VOTING_MACHINE = keccak256(moc.voting-machine)
    bytes32 public constant MOC_VOTING_MACHINE =
        0xc0ded27704f62d8726fdbd83648113d9fd8cf32c09f80523d2ba523e0bbd5ba4;

    // MOC_UPGRADE_DELEGATOR = keccak256(moc.upgrade-delegator)
    bytes32 public constant MOC_UPGRADE_DELEGATOR =
        0x631bcbb9b033f9c8d13c32cf6e60827348d77b91b58c295e87745219242cca22;

    // MOC_PRICE_PROVIDER_REGISTRY = keccak256(moc.price-provider-registy)
    bytes32 public constant MOC_PRICE_PROVIDER_REGISTRY =
        0xd4ed72d0bf9bae5e1e7ae31a372a37c8069168889284ec94be25b3f6707f5b4a;

    // MOC_VOTING_MACHINE_MIN_STAKE = keccak256(moc.voting-machine.minStake)
    bytes32 public constant MOC_VOTING_MACHINE_MIN_STAKE =
        0x580be8e098dd1016787d59c2a534bf9df9ec679a29de4c8f92dc3807f7d7d54d;

    // MOC_VOTING_MACHINE_PRE_VOTE_EXPIRATION_TIME_DELTA = keccak256(moc.voting-machine.preVoteExpirationTimeDelta)
    bytes32 public constant MOC_VOTING_MACHINE_PRE_VOTE_EXPIRATION_TIME_DELTA =
        0x62f5dbf0c17b0df83487409f747ad2eeca5fd54c140ca59b32cf39d6f6eaf916;

    // MOC_VOTING_MACHINE_MAX_PRE_PROPOSALS = keccak256(moc.voting-machine.maxPreProposals)
    bytes32 public constant MOC_VOTING_MACHINE_MAX_PRE_PROPOSALS =
        0xc32b9cbc59039d297e670e7c196424308c90ba4a437fa7ccd008498c934e7dbf;

    // MOC_VOTING_MACHINE_PRE_VOTE_MIN_PCT_TO_WIN = keccak256(moc.voting-machine.preVoteMinPCToWin)
    bytes32 public constant MOC_VOTING_MACHINE_PRE_VOTE_MIN_PCT_TO_WIN =
        0x0a1b21dfd7e4f3741529cf579e2731e847d81bbf13a82d0eba6910d7ac4c1c0a;

    // MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_VETO = keccak256(moc.voting-machine.voteMinPctToVeto)
    bytes32 public constant MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_VETO =
        0xfb2d33acd65c36f68a15f8fe41cb8c0dd1eda164ffa87c6882e685ccb1c1adfb;

    // MOC_VOTING_MACHINE_VOTE_MIN_PCT_FOR_QUORUM = keccak256(moc.voting-machine.voteMinPctForQuorum)
    bytes32 public constant MOC_VOTING_MACHINE_VOTE_MIN_PCT_FOR_QUORUM =
        0xde1ede48948567c43c504b761af8cd6af5363fafeceb1239b3083955d809714f;

    // MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_ACCEPT = keccak256(moc.voting-machine.voteMinPctToAccept)
    bytes32 public constant MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_ACCEPT =
        0x99f83ee0c57b325f3deafb536d55596743ff112c6ac0d853d5f4f89b75dec045;

    // MOC_VOTING_MACHINE_PCT_PRECISION = keccak256(moc.voting-machine.PCTPrecision)
    bytes32 public constant MOC_VOTING_MACHINE_PCT_PRECISION =
        0x73ee596441ef88c207a7a9147d62f59186b4991555e37b7ce9c801f9539d1050;

    // MOC_VOTING_MACHINE_VOTING_TIME_DELTA = keccak256(moc.voting-machine.votingTimeDelta)
    bytes32 public constant MOC_VOTING_MACHINE_VOTING_TIME_DELTA =
        0xb43ee0a5ee6dcc7115ce824e4e353526ad6e479afa4daeb78451070de942de36;

    // ORACLE_MANAGER_ADDR = keccak256(MOC_ORACLE\1\ORACLE_MANAGER_ADDR)
    bytes32 public constant ORACLE_MANAGER_ADDR =
        0x16986f74674f2ed21d50b6e74e6b12bb323ff4f72364542fd5de5104f3cc3ca9;

    // SUPPORTERS_ADDR = keccak256(MOC_ORACLE\1\SUPPORTERS_ADDR)
    bytes32 public constant SUPPORTERS_ADDR =
        0xe4f979504d2a7a24557a15195eb83131e7c4a66d33900454705435aa5a6ee086;

    // INFO_ADDR = keccak256(MOC_ORACLE\1\INFO_ADDR)
    bytes32 public constant INFO_ADDR =
        0xda9f12e01fc92de345bb741448d36ecb967052dd7aa1670439af833c9a3d78f1;

    // ORACLE_PRICE_FETCH_RATE = keccak256(MOC_ORACLE\1\ORACLE_PRICE_FETCH_RATE)
    bytes32 public constant ORACLE_PRICE_FETCH_RATE =
        0x945f72e5d44fb0ce3b1de393d19415723b79f97ad801089d8470d1c20e15ffef;

    // ORACLE_BLOCKCHAIN_INFO_INTERVAL = keccak256(MOC_ORACLE\1\ORACLE_BLOCKCHAIN_INFO_INTERVAL)
    bytes32 public constant ORACLE_BLOCKCHAIN_INFO_INTERVAL =
        0x11cfbdf601b80a575e4366f0234cc06de0c9f401fe250dd9dccfccefeedb6fc2;

    // ORACLE_COIN_PAIR_LOOP_TASK_INTERVAL = keccak256(MOC_ORACLE\1\ORACLE_COIN_PAIR_LOOP_TASK_INTERVAL)
    bytes32 public constant ORACLE_COIN_PAIR_LOOP_TASK_INTERVAL =
        0x2f271dc1fa81985bda14a2d6d0d60b45191d2a2d97e636b192696a8796d654a7;

    // ORACLE_MAIN_LOOP_TASK_INTERVAL = keccak256(MOC_ORACLE\1\ORACLE_MAIN_LOOP_TASK_INTERVAL)
    bytes32 public constant ORACLE_MAIN_LOOP_TASK_INTERVAL =
        0x275d8a46b817572476d2d55b41c7709dee307740bad676a9693805003a48d231;

    // ORACLE_PRICE_REJECT_DELTA_PCT = keccak256(MOC_ORACLE\1\ORACLE_PRICE_REJECT_DELTA_PCT)
    bytes32 public constant ORACLE_PRICE_REJECT_DELTA_PCT =
        0x7a3ee46ca1bd3e19089870d8d6530b083a86da93aab52efccb32d5950e2709cf;

    // ORACLE_CONFIGURATION_TASK_INTERVAL = keccak256(MOC_ORACLE\1\ORACLE_CONFIGURATION_TASK_INTERVAL)
    bytes32 public constant ORACLE_CONFIGURATION_TASK_INTERVAL =
        0xb027f2006a45346de89db4c5efc53f4e05e96532d27366aff00367a394d0abc4;

    // ORACLE_GATHER_SIGNATURE_TIMEOUT = keccak256(MOC_ORACLE\1\ORACLE_GATHER_SIGNATURE_TIMEOUT)
    bytes32 public constant ORACLE_GATHER_SIGNATURE_TIMEOUT =
        0xf75b08b2b912abdbb87cc459ca0b4fdc019329386ec84ab68399b0c86fed5a95;

    // ORACLE_MAIN_EXECUTOR_TASK_INTERVAL = keccak256(MOC_ORACLE\1\ORACLE_MAIN_EXECUTOR_TASK_INTERVAL)
    bytes32 public constant ORACLE_MAIN_EXECUTOR_TASK_INTERVAL =
        0xb324a91be1ac0d0c4888c835aee124ca1a7caf4b73ce10aa3504e2683865d7e5;

    // SCHEDULER_POOL_DELAY = keccak256(MOC_ORACLE\1\SCHEDULER_POOL_DELAY)
    bytes32 public constant SCHEDULER_POOL_DELAY =
        0x6c2abc911c0fa4c73b90c7143a9f4429749be45ebfe7b81e69b86e7ca440d811;

    // SCHEDULER_ROUND_DELAY = keccak256(MOC_ORACLE\1\SCHEDULER_ROUND_DELAY)
    bytes32 public constant SCHEDULER_ROUND_DELAY =
        0xa82bea7140872d1398fa0ab5075330ab0228f4c7e381b4b6502379ffc7cdcd9f;

    // ORACLE_PRICE_DIGITS = keccak256(MOC_ORACLE\1\ORACLE_PRICE_DIGITS)
    bytes32 public constant ORACLE_PRICE_DIGITS =
        0x4cd7e3f12ee4a2db0a6ba16e03fbc31bba1048c149bbf4fc9f3c02021ec550b8;

    // ORACLE_QUEUE_LEN = keccak256(MOC_ORACLE\1\ORACLE_QUEUE_LEN)
    bytes32 public constant ORACLE_QUEUE_LEN =
        0x7d32d87d65898c3cbc7e72c59d223bf61c7811e99dafafd24fb08e0a38f10914;

    // MESSAGE_VERSION = keccak256(MOC_ORACLE\1\MESSAGE_VERSION)
    bytes32 public constant MESSAGE_VERSION =
        0xeafac1a2b4d4fdcc942cbdce334a88ec83387087978d039f1320d3639a0b59df;

    // ORACLE_PRICE_DELTA_PCT = keccak256(MOC_ORACLE\1\ORACLE_PRICE_DELTA_PCT)
    bytes32 public constant ORACLE_PRICE_DELTA_PCT =
        0x41a2ac05b365409628009a8091d8dda06fe52fe2f1c792e651e5df7599a7a7de;

    // ORACLE_PRICE_PUBLISH_BLOCKS = keccak256(MOC_ORACLE\1\ORACLE_PRICE_PUBLISH_BLOCKS)
    bytes32 public constant ORACLE_PRICE_PUBLISH_BLOCKS =
        0x51a2be29a473202678b6cf57b717ba5d7ff671f01fdbdbfcad4e1882601b8896;

    // ORACLE_ENTERING_FALLBACKS_AMOUNTS = keccak256(MOC_ORACLE\1\ORACLE_ENTERING_FALLBACKS_AMOUNTS)
    bytes32 public constant ORACLE_ENTERING_FALLBACKS_AMOUNTS =
        0xf646c455329c7af0436f9e95c59c90ce0e11bb4e3a1deff805807798696adf88;

    // ORACLE_TRIGGER_VALID_PUBLICATION_BLOCKS = keccak256(MOC_ORACLE\1\ORACLE_TRIGGER_VALID_PUBLICATION_BLOCKS)
    bytes32 public constant ORACLE_TRIGGER_VALID_PUBLICATION_BLOCKS =
        0xef9006fe6663199909dfaa4ab45e3f86d6454adb7773682f356824b6b3bc6b0e;

    // ORACLE_MIN_ORACLES_PER_ROUND = keccak256(MOC_ORACLE\1\ORACLE_MIN_ORACLES_PER_ROUND)
    bytes32 public constant ORACLE_MIN_ORACLES_PER_ROUND =
        0xf5afc54dd2c3e35bfa15485ed117b621cf51f31f803d11be832ccde6c77a6b56;

    // MOC_FLOW_BUFFERS = keccak256(MOC_FLOW\1\BUFFERS)
    bytes32 public constant MOC_FLOW_BUFFERS =
        0x4cb845794d5472a713e41e8e4ddc566dab8d695f1dc6c8edd43dad9d55112a22;

    // MOC_FLOW_DRIPPERS = keccak256(MOC_FLOW\1\DRIPPERS)
    bytes32 public constant MOC_FLOW_DRIPPERS =
        0xdd6eacd9b2305faa48e6e500ef302cf28b8cd660dc843b355a6f5f26655eee73;

    // MOC_FLOW_COINERS = keccak256(MOC_FLOW\1\COINERS)
    bytes32 public constant MOC_FLOW_COINERS =
        0x8970fe7a53b9c3dfce4f2afec48b5a6550afcb16ea2da8a10ec4b47a83a34a9d;

    // MOC_FLOW_REVERSE_AUCTIONS = keccak256(MOC_FLOW\1\REVERSE_AUCTIONS)
    bytes32 public constant MOC_FLOW_REVERSE_AUCTIONS =
        0x0428ec087e0cce276a71d1caf1afe4da32a2d48b3ebe579040612b5bd262ff73;
}

library RegistryConstantsLib {
    function MOC_PROJECT_VERSION() internal pure returns (bytes32) {
        // keccak256(moc.project.version)
        return 0xc1c87e0508bb8270ee6a6dbe630baa072e6e3d5968981666724b9333430e1c31;
    }

    function MOC_TOKEN() internal pure returns (bytes32) {
        // keccak256(moc.token)
        return 0x4bd5e7ff929fdd1ba62a33f76e0f40e97bb35e8bf126c0d9d91ce5c69a4bc521;
    }

    function MOC_DELAY_MACHINE() internal pure returns (bytes32) {
        // keccak256(moc.delay-machine)
        return 0x66b60892ff6e7f0da16db27046f5960fdfd6bce5c3c8c21d56ccca3236a6281b;
    }

    function MOC_STAKING_MACHINE() internal pure returns (bytes32) {
        // keccak256(moc.staking-machine)
        return 0x3c557531fea67120f21bc7711270a96f1b8cff3dfe3dd798a8a9f09ce9b77972;
    }

    function MOC_VESTING_MACHINE() internal pure returns (bytes32) {
        // keccak256(moc.vesting-machine)
        return 0x7dfea4fb968e2599cdb7b3028c07d0188d0f92d1d00bd95c2805523c224649dd;
    }

    function MOC_VOTING_MACHINE() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine)
        return 0xc0ded27704f62d8726fdbd83648113d9fd8cf32c09f80523d2ba523e0bbd5ba4;
    }

    function MOC_UPGRADE_DELEGATOR() internal pure returns (bytes32) {
        // keccak256(moc.upgrade-delegator)
        return 0x631bcbb9b033f9c8d13c32cf6e60827348d77b91b58c295e87745219242cca22;
    }

    function MOC_PRICE_PROVIDER_REGISTRY() internal pure returns (bytes32) {
        // keccak256(moc.price-provider-registy)
        return 0xd4ed72d0bf9bae5e1e7ae31a372a37c8069168889284ec94be25b3f6707f5b4a;
    }

    function MOC_VOTING_MACHINE_MIN_STAKE() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.minStake)
        return 0x580be8e098dd1016787d59c2a534bf9df9ec679a29de4c8f92dc3807f7d7d54d;
    }

    function MOC_VOTING_MACHINE_PRE_VOTE_EXPIRATION_TIME_DELTA() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.preVoteExpirationTimeDelta)
        return 0x62f5dbf0c17b0df83487409f747ad2eeca5fd54c140ca59b32cf39d6f6eaf916;
    }

    function MOC_VOTING_MACHINE_MAX_PRE_PROPOSALS() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.maxPreProposals)
        return 0xc32b9cbc59039d297e670e7c196424308c90ba4a437fa7ccd008498c934e7dbf;
    }

    function MOC_VOTING_MACHINE_PRE_VOTE_MIN_PCT_TO_WIN() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.preVoteMinPCToWin)
        return 0x0a1b21dfd7e4f3741529cf579e2731e847d81bbf13a82d0eba6910d7ac4c1c0a;
    }

    function MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_VETO() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.voteMinPctToVeto)
        return 0xfb2d33acd65c36f68a15f8fe41cb8c0dd1eda164ffa87c6882e685ccb1c1adfb;
    }

    function MOC_VOTING_MACHINE_VOTE_MIN_PCT_FOR_QUORUM() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.voteMinPctForQuorum)
        return 0xde1ede48948567c43c504b761af8cd6af5363fafeceb1239b3083955d809714f;
    }

    function MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_ACCEPT() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.voteMinPctToAccept)
        return 0x99f83ee0c57b325f3deafb536d55596743ff112c6ac0d853d5f4f89b75dec045;
    }

    function MOC_VOTING_MACHINE_PCT_PRECISION() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.PCTPrecision)
        return 0x73ee596441ef88c207a7a9147d62f59186b4991555e37b7ce9c801f9539d1050;
    }

    function MOC_VOTING_MACHINE_VOTING_TIME_DELTA() internal pure returns (bytes32) {
        // keccak256(moc.voting-machine.votingTimeDelta)
        return 0xb43ee0a5ee6dcc7115ce824e4e353526ad6e479afa4daeb78451070de942de36;
    }

    function ORACLE_MANAGER_ADDR() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_MANAGER_ADDR)
        return 0x16986f74674f2ed21d50b6e74e6b12bb323ff4f72364542fd5de5104f3cc3ca9;
    }

    function SUPPORTERS_ADDR() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\SUPPORTERS_ADDR)
        return 0xe4f979504d2a7a24557a15195eb83131e7c4a66d33900454705435aa5a6ee086;
    }

    function INFO_ADDR() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\INFO_ADDR)
        return 0xda9f12e01fc92de345bb741448d36ecb967052dd7aa1670439af833c9a3d78f1;
    }

    function ORACLE_PRICE_FETCH_RATE() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_PRICE_FETCH_RATE)
        return 0x945f72e5d44fb0ce3b1de393d19415723b79f97ad801089d8470d1c20e15ffef;
    }

    function ORACLE_BLOCKCHAIN_INFO_INTERVAL() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_BLOCKCHAIN_INFO_INTERVAL)
        return 0x11cfbdf601b80a575e4366f0234cc06de0c9f401fe250dd9dccfccefeedb6fc2;
    }

    function ORACLE_COIN_PAIR_LOOP_TASK_INTERVAL() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_COIN_PAIR_LOOP_TASK_INTERVAL)
        return 0x2f271dc1fa81985bda14a2d6d0d60b45191d2a2d97e636b192696a8796d654a7;
    }

    function ORACLE_MAIN_LOOP_TASK_INTERVAL() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_MAIN_LOOP_TASK_INTERVAL)
        return 0x275d8a46b817572476d2d55b41c7709dee307740bad676a9693805003a48d231;
    }

    function ORACLE_PRICE_REJECT_DELTA_PCT() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_PRICE_REJECT_DELTA_PCT)
        return 0x7a3ee46ca1bd3e19089870d8d6530b083a86da93aab52efccb32d5950e2709cf;
    }

    function ORACLE_CONFIGURATION_TASK_INTERVAL() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_CONFIGURATION_TASK_INTERVAL)
        return 0xb027f2006a45346de89db4c5efc53f4e05e96532d27366aff00367a394d0abc4;
    }

    function ORACLE_GATHER_SIGNATURE_TIMEOUT() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_GATHER_SIGNATURE_TIMEOUT)
        return 0xf75b08b2b912abdbb87cc459ca0b4fdc019329386ec84ab68399b0c86fed5a95;
    }

    function ORACLE_MAIN_EXECUTOR_TASK_INTERVAL() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_MAIN_EXECUTOR_TASK_INTERVAL)
        return 0xb324a91be1ac0d0c4888c835aee124ca1a7caf4b73ce10aa3504e2683865d7e5;
    }

    function SCHEDULER_POOL_DELAY() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\SCHEDULER_POOL_DELAY)
        return 0x6c2abc911c0fa4c73b90c7143a9f4429749be45ebfe7b81e69b86e7ca440d811;
    }

    function SCHEDULER_ROUND_DELAY() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\SCHEDULER_ROUND_DELAY)
        return 0xa82bea7140872d1398fa0ab5075330ab0228f4c7e381b4b6502379ffc7cdcd9f;
    }

    function ORACLE_PRICE_DIGITS() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_PRICE_DIGITS)
        return 0x4cd7e3f12ee4a2db0a6ba16e03fbc31bba1048c149bbf4fc9f3c02021ec550b8;
    }

    function ORACLE_QUEUE_LEN() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_QUEUE_LEN)
        return 0x7d32d87d65898c3cbc7e72c59d223bf61c7811e99dafafd24fb08e0a38f10914;
    }

    function MESSAGE_VERSION() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\MESSAGE_VERSION)
        return 0xeafac1a2b4d4fdcc942cbdce334a88ec83387087978d039f1320d3639a0b59df;
    }

    function ORACLE_PRICE_DELTA_PCT() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_PRICE_DELTA_PCT)
        return 0x41a2ac05b365409628009a8091d8dda06fe52fe2f1c792e651e5df7599a7a7de;
    }

    function ORACLE_PRICE_PUBLISH_BLOCKS() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_PRICE_PUBLISH_BLOCKS)
        return 0x51a2be29a473202678b6cf57b717ba5d7ff671f01fdbdbfcad4e1882601b8896;
    }

    function ORACLE_ENTERING_FALLBACKS_AMOUNTS() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_ENTERING_FALLBACKS_AMOUNTS)
        return 0xf646c455329c7af0436f9e95c59c90ce0e11bb4e3a1deff805807798696adf88;
    }

    function ORACLE_TRIGGER_VALID_PUBLICATION_BLOCKS() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_TRIGGER_VALID_PUBLICATION_BLOCKS)
        return 0xef9006fe6663199909dfaa4ab45e3f86d6454adb7773682f356824b6b3bc6b0e;
    }

    function ORACLE_MIN_ORACLES_PER_ROUND() internal pure returns (bytes32) {
        // keccak256(MOC_ORACLE\1\ORACLE_MIN_ORACLES_PER_ROUND)
        return 0xf5afc54dd2c3e35bfa15485ed117b621cf51f31f803d11be832ccde6c77a6b56;
    }

    function MOC_FLOW_BUFFERS() internal pure returns (bytes32) {
        // keccak256(MOC_FLOW\1\BUFFERS)
        return 0x4cb845794d5472a713e41e8e4ddc566dab8d695f1dc6c8edd43dad9d55112a22;
    }

    function MOC_FLOW_DRIPPERS() internal pure returns (bytes32) {
        // keccak256(MOC_FLOW\1\DRIPPERS)
        return 0xdd6eacd9b2305faa48e6e500ef302cf28b8cd660dc843b355a6f5f26655eee73;
    }

    function MOC_FLOW_COINERS() internal pure returns (bytes32) {
        // keccak256(MOC_FLOW\1\COINERS)
        return 0x8970fe7a53b9c3dfce4f2afec48b5a6550afcb16ea2da8a10ec4b47a83a34a9d;
    }

    function MOC_FLOW_REVERSE_AUCTIONS() internal pure returns (bytes32) {
        // keccak256(MOC_FLOW\1\REVERSE_AUCTIONS)
        return 0x0428ec087e0cce276a71d1caf1afe4da32a2d48b3ebe579040612b5bd262ff73;
    }
}


/*
    Abstract contract meant to be reused.
*/
library VestingLib {
    uint256 public constant PERCENTAGES_BASE = 10000;

    using SafeMath for uint256;
    using AddressSetLib for AddressSetLib.AddressSet;

    // Global data
    struct VestingData {
        // @dev Percentages array of locked funds at a given time,
        // percentages are in fixed point with 4 decimals,
        // percentages should be in decreasing order.
        // Example: percentages = [9000, 5000, 0]
        uint256[] percentages;
        // @dev Time deltas array when percentages become active,
        // time deltas should sorted in increasing order,
        // time deltas are measured from the TGE event,
        // time deltas are expressed in seconds.
        // Example: timedeltas = [2592000, 7776000, 15552000]
        uint256[] timedeltas;
        // @dev Address of holder
        address holder;
        // @dev Vesting Factory
        VestingFactory vestingFactory;
        // @dev Registry contracts
        IRegistry registry;
        // @dev Indicates if holder has verified the contract
        bool verified;
        // @dev Total vesting
        uint256 total;
        // @dev Contract that can be called with callWithData
        AddressSetLib.AddressSet whitelistedContracts;
    }

    /**
        Contract creation

        @param _holder address who will able to withdraw tokens when released
    */
    function _initialize(
        VestingData storage self,
        VestingFactory _vestingFactory,
        address _holder
    ) internal {
        self.holder = _holder;
        self.verified = false;
        require(_vestingFactory != VestingFactory(0), "Invalid vestingFactory address");
        self.vestingFactory = _vestingFactory;
        self.registry = _vestingFactory.getRegistry();
        self.whitelistedContracts.add(address(_getDelayMachine(self)));
        self.whitelistedContracts.add(address(_getStakingMachine(self)));
        self.whitelistedContracts.add(address(_getVotingMachine(self)));
    }

    /**
     * @notice Retrieve vesting parameters
     */
    function _getParameters(VestingData storage self)
        internal
        view
        returns (uint256[] memory, uint256[] memory)
    {
        return (self.percentages, self.timedeltas);
    }

    /**
     * @notice Mark contract as verified by holder
     */
    function _verify(VestingData storage self) internal {
        require(msg.sender == self.holder, "Only holder can verify contract");
        self.verified = true;
    }

    /**
     * @notice Change holder address
     * @param _newHolder the new holder
     */
    function _setHolder(VestingData storage self, address _newHolder) internal {
        require(msg.sender == address(self.vestingFactory), "Only factory can change holder");
        require(!_isVerified(self), "Cannot change after verification");
        self.holder = _newHolder;
    }

    /**
     * @notice Calls a function from target passing data
     * @param target Target contract to call
     * @param data Data to pass target contract
     */
    function _callWithData(
        VestingData storage self,
        address target,
        bytes memory data
    ) internal {
        require(msg.sender == self.holder, "Holder is required");
        require(self.whitelistedContracts.contains(target), "Invalid target");
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, ) = target.call(data);
        require(success, "CallWithData failed");
    }

    /**
     * @notice approve a transfer to the staking machine.
     * @param amount Token amount to approve
     */
    function approve(VestingData storage self, uint256 amount) internal {
        require(msg.sender == self.holder, "Holder is required");
        _approve(self, amount);
    }

    /**
     * @notice deposit MOCs in the staking machine
     * @param amount Token amount to approve
     */
    function _deposit(VestingData storage self, uint256 amount) internal {
        require(msg.sender == self.holder, "Holder is required");
        IStakingMachine stakingMachine = _getStakingMachine(self);
        _approve(self, amount);
        stakingMachine.deposit(amount, address(this));
    }

    /**
     * @notice Withdraws tokens to holder address
     * @param amount Tokens amount to withdraw
     * @return Returns true on success
     */
    function _withdraw(VestingData storage self, uint256 amount) internal returns (bool) {
        require(_isVerified(self), "Holder should verify");
        require(msg.sender == self.holder, "Holder is required");
        uint256 freeMocs = _getAvailable(self);
        require(amount <= freeMocs, "Not enough mocs to withdraw");
        IERC20 token = _getToken(self);
        require(token.transfer(msg.sender, amount), "Withdraw failed");
        return true;
    }

    /**
     * @notice Withdraws all available tokens to holder address
     * @return Returns true on success
     */
    function _withdrawAll(VestingData storage self) internal returns (bool) {
        require(msg.sender == self.holder, "Holder is required");
        uint256 amount = _getAvailable(self);
        require(amount > 0, "Not enough mocs to withdraw");
        IERC20 token = _getToken(self);
        require(token.transfer(msg.sender, amount), "Withdraw failed");
        return true;
    }

    /**
     * @notice Configure vesting total balance
     */
    function _setTotal(VestingData storage self, uint256 amount) internal {
        require(msg.sender == address(self.vestingFactory), "Only factory allowed");
        self.total = amount;
    }

    /**
     * @notice Token amount available for withdrawal
     */
    function _getAvailable(VestingData storage self) internal view returns (uint256) {
        if (!_isWithdrawEnabled(self)) {
            // Withdraw not enabled
            return 0;
        }
        // Minimum token amount to be locked in vesting contract
        uint256 minimumLocked = _getLocked(self);
        // Tokens locked in outside contracts
        uint256 lockedOutside = _getStakingBalance(self);
        lockedOutside = lockedOutside.add(_getDelayBalance(self));
        if (minimumLocked >= lockedOutside) {
            minimumLocked = minimumLocked.sub(lockedOutside);
        } else {
            minimumLocked = 0;
        }
        uint256 balance = _getTokenBalance(self);
        // Available mocs for withdrawal
        uint256 freeMocs = 0;
        if (balance >= minimumLocked) {
            freeMocs = balance.sub(minimumLocked);
        }
        return freeMocs;
    }

    function _isVerified(VestingData storage self) internal view returns (bool) {
        return self.verified;
    }

    /**
     * @notice Minimum token amount required to be locked
     */
    function _getLocked(VestingData storage self) internal view returns (uint256) {
        // solhint-disable-next-line not-rely-on-time
        return _getLockedAt(self, block.timestamp);
    }

    /**
     * @notice Minimum token amount required to be locked
     * @param timestamp date to check
     */
    function _getLockedAt(VestingData storage self, uint256 timestamp)
        internal
        view
        returns (uint256)
    {
        if (!self.vestingFactory.isTGEConfigured()) {
            // TGE not configured yet
            return self.total;
        }
        uint256 tgeTimestamp = self.vestingFactory.getTGETimestamp();
        if (timestamp <= tgeTimestamp) {
            // Can't withdraw at a time prior to the TGE
            return self.total;
        }
        // Time deltas are base from the TGE event and they are expressed in days
        uint256 delta = timestamp.sub(tgeTimestamp);
        uint256 i = 0;
        // Search i such that timedeltas[i-1] <= delta < timedeltas[i]
        while (i < self.timedeltas.length && delta >= self.timedeltas[i]) {
            i += 1;
        }
        if (i >= self.timedeltas.length) {
            // All funds are available
            return 0;
        } else if (i == 0) {
            return self.total;
        } else {
            return (self.total.mul(self.percentages[i - 1])).div(PERCENTAGES_BASE);
        }
    }

    /**
     * @notice Add an address to the whitelisted contracts
     * @param addr address to add
     */
    function _addToWhitelist(VestingData storage self, address addr) internal returns (bool) {
        require(msg.sender == address(self.vestingFactory), "Only factory allowed");
        return self.whitelistedContracts.add(addr);
    }

    /**
     * @notice Remove an address from the whitelisted contracts
     * @param addr address to add
     */
    function _removeFromWhitelist(VestingData storage self, address addr) internal returns (bool) {
        require(msg.sender == address(self.vestingFactory), "Only factory allowed");
        return self.whitelistedContracts.remove(addr);
    }

    /**
     * @notice Get the whitelisted contracts length
     */
    function _getWhitelistLen(VestingData storage self) internal view returns (uint256) {
        return self.whitelistedContracts.length();
    }

    /**
     * @notice Get the whitelisted contracts length
     * @param idx the index in the whitelist
     */
    function _getWhitelistEntry(VestingData storage self, uint256 idx)
        internal
        view
        returns (address)
    {
        return self.whitelistedContracts.at(idx);
    }

    function _updateParameters(
        VestingData storage self,
        uint256[] memory _percentages,
        uint256[] memory _timedeltas
    ) internal {
        require(_percentages.length == _timedeltas.length, "Arrays length should be equal");
        for (uint256 i = 1; i < _timedeltas.length; i += 1) {
            require(_percentages[i - 1] >= _percentages[i], "Percentages decreasing order");
            require(_timedeltas[i - 1] < _timedeltas[i], "Time deltas increasing order");
        }
        self.percentages = _percentages;
        self.timedeltas = _timedeltas;
    }

    function _approve(VestingData storage self, uint256 amount) internal {
        IERC20 mocToken = _getToken(self);
        require(mocToken.approve(address(_getStakingMachine(self)), amount), "Approve failed");
    }

    function _getToken(VestingData storage self) internal view returns (IERC20) {
        return IERC20(self.registry.getAddress(RegistryConstantsLib.MOC_TOKEN()));
    }

    function _getTokenBalance(VestingData storage self) internal view returns (uint256) {
        return _getToken(self).balanceOf(address(this));
    }

    function _getDelayMachine(VestingData storage self) internal view returns (IDelayMachine) {
        return IDelayMachine(self.registry.getAddress(RegistryConstantsLib.MOC_DELAY_MACHINE()));
    }

    function _getDelayBalance(VestingData storage self) internal view returns (uint256) {
        return _getDelayMachine(self).getBalance(address(this));
    }

    function _getStakingMachine(VestingData storage self) internal view returns (IStakingMachine) {
        return
            IStakingMachine(self.registry.getAddress(RegistryConstantsLib.MOC_STAKING_MACHINE()));
    }

    function _getStakingBalance(VestingData storage self) internal view returns (uint256) {
        return _getStakingMachine(self).getBalance(address(this));
    }

    function _getVotingMachine(VestingData storage self) internal view returns (IVotingMachine) {
        return IVotingMachine(self.registry.getAddress(RegistryConstantsLib.MOC_VOTING_MACHINE()));
    }

    function _isWithdrawEnabled(VestingData storage self) internal view returns (bool) {
        // solhint-disable-next-line not-rely-on-time
        uint256 timestamp = block.timestamp;
        return (self.vestingFactory.isTGEConfigured() &&
            timestamp >= self.vestingFactory.getTGETimestamp());
    }
}


/// @title Vesting contract
/// @notice Release tokens following a release schedule
contract Vesting is IVestingMachine {
    using SafeMath for uint256;
    using VestingLib for VestingLib.VestingData;

    VestingLib.VestingData internal vestingData;

    /// @notice Create a vesting contract
    /// @param _holder address who will able to withdraw tokens when released
    /// @param _percentages array of token percentages locked at a date
    /// @param _timedeltas array of date deltas from TGE when percentages are valid
    constructor(
        address _holder,
        uint256[] memory _percentages,
        uint256[] memory _timedeltas
    ) public {
        vestingData._initialize(VestingFactory(msg.sender), _holder);
        vestingData._updateParameters(_percentages, _timedeltas);
    }

    /// @notice Retrieve vesting parameters
    function getParameters() public view override returns (uint256[] memory, uint256[] memory) {
        return vestingData._getParameters();
    }

    /// @notice Mark contract as verified by holder
    function verify() public override {
        vestingData._verify();
    }

    /// @notice Change holder address
    /// @param newHolder the new holder
    function setHolder(address newHolder) public override {
        vestingData._setHolder(newHolder);
    }

    /// @notice Returns current holder address
    function getHolder() public view override returns (address) {
        return vestingData.holder;
    }

    /// @notice Calls a function from target passing data
    /// @param target Target contract to call
    /// @param data Data to pass target contract
    function callWithData(address target, bytes memory data) public override {
        vestingData._callWithData(target, data);
    }

    /// @notice approve a transfer to the staking machine.
    /// @param amount Token amount to approve
    function approve(uint256 amount) public override {
        vestingData.approve(amount);
    }

    /// @notice deposit MOCs in the staking machine
    /// @param amount Token amount to approve
    function deposit(uint256 amount) public override {
        vestingData._deposit(amount);
    }

    /// @notice Withdraws tokens to holder address
    /// @param amount Tokens amount to withdraw
    /// @return Returns true on success
    function withdraw(uint256 amount) public override returns (bool) {
        return vestingData._withdraw(amount);
    }

    /// @notice Withdraws all available tokens to holder address
    /// @return Returns true on success
    function withdrawAll() public override returns (bool) {
        return vestingData._withdrawAll();
    }

    /// @notice Minimum token amount required to be locked
    /// @param timestamp date to check
    function getLockedAt(uint256 timestamp) public view override returns (uint256) {
        return vestingData._getLockedAt(timestamp);
    }

    /// @notice Minimum token amount required to be locked
    function getLocked() public view override returns (uint256) {
        return vestingData._getLocked();
    }

    /// @notice Token amount available for withdrawal
    function getAvailable() public view override returns (uint256) {
        return vestingData._getAvailable();
    }

    /// @notice Returns true after contract has been verified by holder
    function isVerified() public view override returns (bool) {
        return vestingData._isVerified();
    }

    /// @notice Total token balance configured
    function getTotal() public view override returns (uint256) {
        return vestingData.total;
    }

    /// @notice Configure vesting total balance
    function setTotal(uint256 amount) public override {
        vestingData._setTotal(amount);
    }

    /// @notice Add an address to the whitelisted contracts
    /// @param addr address to add
    function addToWhitelist(address addr) public returns (bool) {
        return vestingData._addToWhitelist(addr);
    }

    /// @notice Remove an address from the whitelisted contracts
    /// @param addr address to add
    function removeFromWhitelist(address addr) public returns (bool) {
        return vestingData._removeFromWhitelist(addr);
    }

    /// @notice Get the whitelisted contracts length
    function getWhitelistLen() public view returns (uint256) {
        return vestingData._getWhitelistLen();
    }

    /// @notice Get the whitelisted contracts length
    /// @param idx the index in the whitelist
    function getWhitelistEntry(uint256 idx) public view returns (address) {
        return vestingData._getWhitelistEntry(idx);
    }
}


contract VestingFactoryStorage is Initializable, Governed, OwnableUpgradeSafe {
    using AddressSetLib for AddressSetLib.AddressSet;

    /// @dev Registry to consult addresses
    IRegistry internal registry;

    /// @dev TGE timestamp
    uint256 internal tgeTimestamp;

    // @dev contract that can be called with callWithData
    AddressSetLib.AddressSet internal vestingMachines;
}


contract VestingFactory is VestingFactoryStorage, IVestingFactory {
    event VestingCreated(address vesting, address holder);

    /// @notice Contract creation
    /// @param _governor The address of the contract which governs this one
    /// @param _registry Registry contracts
    function initialize(IGovernor _governor, IRegistry _registry) external initializer {
        Governed._initialize(_governor);
        __Ownable_init();
        registry = _registry;
        tgeTimestamp = 0;
    }

    /// @notice Create a holder wallet
    /// @param holder wallet's owner
    /// @param percentages percentages allowed in each step
    /// @param timedeltas duration of each step
    function create(
        address holder,
        uint256[] memory percentages,
        uint256[] memory timedeltas
    ) external override onlyOwner {
        Vesting wallet = _createVesting(holder, percentages, timedeltas);
        vestingMachines.add(address(wallet));
        emit VestingCreated(address(wallet), holder);
    }

    function replaceHolder(IVestingMachine wallet, address newHolder) public onlyOwner {
        wallet.setHolder(newHolder);
    }

    /// @notice Set the TGE time enabling holder wallets
    function setTGE() public override onlyOwner {
        require(tgeTimestamp == 0, "TGE already configured");
        // solhint-disable-next-line not-rely-on-time
        tgeTimestamp = block.timestamp;
    }

    /// @notice Returns true when the TGE was configured
    function isTGEConfigured() public view override returns (bool) {
        return tgeTimestamp > 0;
    }

    /// @notice Returns the configured TGE timestamp
    function getTGETimestamp() public view override returns (uint256) {
        return tgeTimestamp;
    }

    /// @notice Set a holder wallet balance
    /// @param wallet the vesting machine
    /// @param amount wallet balance
    function setTotal(IVestingMachine wallet, uint256 amount) public override onlyOwner {
        require(wallet.getTotal() == 0, "Wallet total already configured");
        wallet.setTotal(amount);
    }

    /// @notice Return registry
    function getRegistry() public view override returns (IRegistry) {
        return registry;
    }

    /// @notice Get the length of the list of vesting machines
    function getVestingMachinesLen() public view override returns (uint256) {
        return vestingMachines.length();
    }

    /// @notice Get the an entry of the list of vesting machines
    /// @param idx the index in the list
    function getVestingMachinesEntry(uint256 idx) public view override returns (address) {
        return vestingMachines.at(idx);
    }

    function _createVesting(
        address holder,
        uint256[] memory percentages,
        uint256[] memory timedeltas
    ) internal returns (Vesting) {
        return new Vesting(holder, percentages, timedeltas);
    }
}

