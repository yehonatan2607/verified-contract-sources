// SPDX-License-Identifier: MIT
pragma solidity =0.8.25 >=0.4.16 >=0.8.4 ^0.8.18 ^0.8.20;

// node_modules/@openzeppelin/contracts/utils/cryptography/ECDSA.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/cryptography/ECDSA.sol)

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    /**
     * @dev The signature derives the `address(0)`.
     */
    error ECDSAInvalidSignature();

    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    /**
     * @dev The signature has an S value that is in the upper half order.
     */
    error ECDSAInvalidSignatureS(bytes32 s);

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not
     * return address(0) without also returning an error description. Errors are documented using an enum (error type)
     * and a bytes32 providing additional information about the error.
     *
     * If no error is returned, then the address can be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     */
    function tryRecover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[ERC-2098 short signatures]
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        unchecked {
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            return tryRecover(hash, v, r, s);
        }
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.
     */
    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}

// src/libraries/Flyover.sol

library Flyover {
    enum ProviderType { PegIn, PegOut, Both }

    struct LiquidityProvider {
        uint id;
        address providerAddress;
        bool status;
        ProviderType providerType;
        string name;
        string apiBaseUrl;
    }

    error ProviderNotRegistered(address from);
    error IncorrectContract(address expected, address actual);
    error QuoteNotFound(bytes32 quoteHash);
    error PaymentFailed(address addr, uint amount, bytes reason);
    error EmptyBlockHeader(bytes32 heightOrHash);
    error NoBalance(uint256 wanted, uint256 actual);
    error NoContract(address addr);
    error PaymentNotAllowed();
    /// @notice This error is emitted when the sender is not allowed to perform a specific operation
    /// @param expected the expected sender
    /// @param actual the actual sender
    error InvalidSender(address expected, address actual);
    /// @notice This error is emitted when the amount sent is less than the amount required to pay for the quote
    /// @param amount the amount sent
    /// @param target the amount required to pay for the quote
    error InsufficientAmount(uint256 amount, uint256 target);
    error Overflow(uint256 passedAmount);
    error InvalidAddress(address addr);
    /// @notice Quote was created for a different chain
    /// @param expected The current chain id (block.chainid)
    /// @param actual The chain id in the quote
    error InvalidChainId(uint256 expected, uint256 actual);
    /// @notice Used by whenNotPaused when the system is paused via PauseRegistry
    error EnforcedPause();
}

// node_modules/@openzeppelin/contracts/access/IAccessControl.sol

// OpenZeppelin Contracts (last updated v5.4.0) (access/IAccessControl.sol)

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// src/interfaces/IBridge.sol

interface IBridge {

    receive() external payable;

    function registerBtcTransaction(bytes calldata atx, int256 height, bytes calldata pmt) external;

    function addSignature(bytes calldata pubkey, bytes[] calldata signatures, bytes calldata txhash) external;

    function receiveHeaders(bytes[] calldata blocks) external;

    function receiveHeader(bytes calldata ablock) external returns (int256);

    function createFederation() external returns (int256);

    function addFederatorPublicKey(bytes calldata key) external returns (int256);

    function addFederatorPublicKeyMultikey(bytes calldata btcKey, bytes calldata rskKey,
        bytes calldata mstKey) external returns (int256);

    function commitFederation(bytes calldata hash) external returns (int256);

    function rollbackFederation() external returns (int256);

    function addLockWhitelistAddress(string calldata aaddress, int256 maxTransferValue) external returns (int256);

    function addOneOffLockWhitelistAddress(string calldata aaddress, int256 maxTransferValue)
        external returns (int256);

    function addUnlimitedLockWhitelistAddress(string calldata aaddress) external returns (int256);

    function removeLockWhitelistAddress(string calldata aaddress) external returns (int256);

    function setLockWhitelistDisableBlockDelay(int256 disableDelay) external returns (int256);

    function voteFeePerKbChange(int256 feePerKb) external returns (int256);

    function updateCollections() external;

    function increaseLockingCap(int256 newLockingCap) external returns (bool);

    function registerBtcCoinbaseTransaction(bytes calldata btcTxSerialized, bytes32 blockHash,
        bytes calldata pmtSerialized, bytes32 witnessMerkleRoot, bytes32 witnessReservedValue) external;

    function registerFastBridgeBtcTransaction(bytes calldata btcTxSerialized, uint256 height,
        bytes calldata pmtSerialized, bytes32 derivationArgumentsHash,
        bytes calldata userRefundBtcAddress, address payable liquidityBridgeContractAddress,
        bytes calldata liquidityProviderBtcAddress, bool shouldTransferToContract) external returns (int256);

    function getBtcBlockchainBestChainHeight() external view returns (int);

    function getStateForBtcReleaseClient() external view returns (bytes memory);

    function getStateForDebugging() external view returns (bytes memory);

    function getBtcBlockchainInitialBlockHeight() external view returns (int);

    function getBtcBlockchainBlockHashAtDepth(int256 depth) external view returns (bytes memory);

    function getBtcTxHashProcessedHeight(string calldata hash) external view returns (int64);

    function isBtcTxHashAlreadyProcessed(string calldata hash) external view returns (bool);

    function getFederationAddress() external view returns (string memory);

    function getFederationSize() external view returns (int256);

    function getFederationThreshold() external view returns (int256);

    function getFederatorPublicKey(int256 index) external view returns (bytes memory);

    function getFederatorPublicKeyOfType(int256 index, string calldata atype) external view returns (bytes memory);

    function getFederationCreationTime() external view returns (int256);

    function getFederationCreationBlockNumber() external view returns (int256);

    function getRetiringFederationAddress() external view returns (string memory);

    function getRetiringFederationSize() external view returns (int256);

    function getRetiringFederationThreshold() external view returns (int256);

    function getRetiringFederatorPublicKey(int256 index) external view returns (bytes memory);

    function getRetiringFederatorPublicKeyOfType(int256 index, string calldata atype)
    external view returns (bytes memory);

    function getRetiringFederationCreationTime() external view returns (int256);

    function getRetiringFederationCreationBlockNumber() external view returns (int256);

    function getPendingFederationHash() external view returns (bytes memory);

    function getPendingFederationSize() external view returns (int256);

    function getPendingFederatorPublicKey(int256 index) external view returns (bytes memory);

    function getPendingFederatorPublicKeyOfType(int256 index, string calldata atype)
    external view returns (bytes memory);

    function getLockWhitelistSize() external view returns (int256);

    function getLockWhitelistAddress(int256 index) external view returns (string memory);

    function getLockWhitelistEntryByAddress(string calldata aaddress) external view returns (int256);

    function getFeePerKb() external view returns (int256);

    function getMinimumLockTxValue() external view returns (int256);

    function getBtcTransactionConfirmations(bytes32 txHash, bytes32 blockHash,
        uint256 merkleBranchPath, bytes32[] calldata merkleBranchHashes) external view returns (int256);

    function getLockingCap() external view returns (int256);

    function hasBtcBlockCoinbaseTransactionInformation(bytes32 blockHash) external view returns (bool);

    function getActiveFederationCreationBlockHeight() external view returns (uint256);

    function getActivePowpegRedeemScript() external view returns (bytes memory);

    function getBtcBlockchainBestBlockHeader() external view returns (bytes memory);

    function getBtcBlockchainBlockHeaderByHash(bytes32 btcBlockHash) external view returns (bytes memory);

    function getBtcBlockchainBlockHeaderByHeight(uint256 btcBlockHeight) external view returns (bytes memory);

    function getBtcBlockchainParentBlockHeaderByHash(bytes32 btcBlockHash) external view returns (bytes memory);
}

// node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol

// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/IERC165.sol)

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// node_modules/@openzeppelin/contracts/interfaces/IERC5267.sol

// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC5267.sol)

interface IERC5267 {
    /**
     * @dev MAY be emitted to signal that the domain could have changed.
     */
    event EIP712DomainChanged();

    /**
     * @dev returns the fields and values that describe the domain separator used by this contract for EIP-712
     * signature.
     */
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}

// node_modules/@openzeppelin/contracts/interfaces/IERC5313.sol

// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/IERC5313.sol)

/**
 * @dev Interface for the Light Contract Ownership Standard.
 *
 * A standardized minimal interface required to identify an account that controls a contract
 */
interface IERC5313 {
    /**
     * @dev Gets the address of the owner.
     */
    function owner() external view returns (address);
}

// src/interfaces/IPausable.sol

interface IPausable {
    /// @notice Returns the pause status (from the central PauseRegistry)
    /// @return isPaused Whether the system is paused
    /// @return reason The reason for pausing
    /// @return since The timestamp when the system was paused
    function pauseStatus() external view returns (bool isPaused, string memory reason, uint64 since);
}

// src/interfaces/IPauseRegistry.sol

interface IPauseRegistry {
    /// @notice Pauses the system (all contracts using this registry)
    /// @param reason The reason for pausing
    function pause(string calldata reason) external;

    /// @notice Unpauses the system
    function unpause() external;

    /// @notice Returns whether the system is paused
    /// @return True if paused
    function paused() external view returns (bool);

    /// @notice Returns full pause status
    /// @return isPaused Whether the system is paused
    /// @return reason The reason for pausing
    /// @return since The timestamp when the system was paused
    function pauseStatus()
        external
        view
        returns (bool isPaused, string memory reason, uint64 since);
}

// node_modules/@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol

// OpenZeppelin Contracts (last updated v5.3.0) (proxy/utils/Initializable.sol)

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reinitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Pointer to storage slot. Allows integrators to override it with a custom storage location.
     *
     * NOTE: Consider following the ERC-7201 formula to derive storage locations.
     */
    function _initializableStorageSlot() internal pure virtual returns (bytes32) {
        return INITIALIZABLE_STORAGE;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        bytes32 slot = _initializableStorageSlot();
        assembly {
            $.slot := slot
        }
    }
}

// node_modules/@rsksmart/btc-transaction-solidity-helper/contracts/OpCodes.sol

library OpCodes {
    bytes1 public constant OP_DROP = 0x75;
    bytes1 public constant OP_DUP = 0x76;
    bytes1 public constant OP_HASH160 = 0xa9;
    bytes1 public constant OP_EQUALVERIFY = 0x88;
    bytes1 public constant OP_CHECKSIG = 0xac;
    bytes1 public constant OP_RETURN = 0x6a;
    bytes1 public constant OP_EQUAL = 0x87;

    bytes1 public constant OP_PUSHBYTES_32 = 0x20;

    bytes1 public constant OP_0 = 0x00;
    bytes1 public constant OP_1 = 0x51;
}

// node_modules/@openzeppelin/contracts/utils/Panic.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}

// src/libraries/Quotes.sol

library Quotes {
    struct PegInQuote {
        uint256 chainId;
        uint256 callFee;
        uint256 penaltyFee;
        uint256 value;
        uint256 gasFee;
        bytes20 fedBtcAddress;
        address lbcAddress;
        address liquidityProviderRskAddress;
        address contractAddress;
        address payable rskRefundAddress;
        int64 nonce;
        uint32 gasLimit;
        uint32 agreementTimestamp;
        uint32 timeForDeposit;
        uint32 callTime;
        uint16 depositConfirmations;
        bool callOnRegister;
        bytes btcRefundAddress;
        bytes liquidityProviderBtcAddress;
        bytes data;
    }

    struct PegOutQuote {
        uint256 chainId;
        uint256 callFee;
        uint256 penaltyFee;
        uint256 value;
        uint256 gasFee;
        address lbcAddress;
        address lpRskAddress;
        address rskRefundAddress;
        int64   nonce;
        uint32  agreementTimestamp;
        uint32  depositDateLimit;
        uint32  transferTime;
        uint32  expireDate;
        uint32  expireBlock;
        uint16  depositConfirmations;
        uint16  transferConfirmations;
        bytes depositAddress;
        bytes btcRefundAddress;
        bytes lpBtcAddress;
    }

    uint256 public constant SAT_TO_WEI_CONVERSION = 10**10;

    /// @notice The type hash of the PegInQuote struct for EIP712
    /// @dev Due to the number of fields present in the struct, we'll just use the hash of the quote and the
    /// address of the liquidity provider offering it to calculate the EIP712 hash. In this way we avoid issues
    /// with stack depth limits and future modifications to the type hash based on changes in the struct.
    /// @dev keccak256("PegInQuote(address liquidityProvider,bytes32 quoteHash)")
    bytes32 public constant PEG_IN_QUOTE_TYPE_HASH = 0x82b0b35cb5a2b2130657be6794570d328b06b7687bdff463bce4a0cc24a880a2;

    /// @notice The type hash of the PegOutQuote struct for EIP712
    /// @dev Due to the number of fields present in the struct, we'll just use the hash of the quote and the
    /// address of the liquidity provider offering it to calculate the EIP712 hash. In this way we avoid issues
    /// with stack depth limits and future modifications to the type hash based on changes in the struct.
    /// @dev keccak256("PegOutQuote(address liquidityProvider,bytes32 quoteHash)")
    bytes32 public constant PEG_OUT_QUOTE_TYPE_HASH =
        0x940deda477f28e6fd80f8307aea1edb500dbd4ee20815878162fec9001fab898;

    error AmountTooLow(uint256 value, uint256 target);

    function checkAgreedAmount(
        PegInQuote calldata quote,
        uint transferredAmount
    ) external pure {
        uint agreedAmount = 0;
        agreedAmount = quote.value + quote.callFee + quote.gasFee;

        // Adjust for rounding when converting from wei to sats and back
        // This protects users from precision issues when client apps don't round properly
        if (agreedAmount > SAT_TO_WEI_CONVERSION && (agreedAmount % SAT_TO_WEI_CONVERSION) != 0) {
            agreedAmount -= (agreedAmount % SAT_TO_WEI_CONVERSION);
        }

        // transferred amount should not be lower than agreed amount
        if (agreedAmount > transferredAmount) {
            revert AmountTooLow(transferredAmount, agreedAmount);
        }
    }

    /// @notice This function is used to get the hashStruct of a peg in quote using EIP712 specification
    /// @dev The hashStruct should be later combined with the domain separator to get the final hash
    /// @param quote The peg in quote to hash
    /// @return hashStruct The hash struct to be combined with the domain separator
    function hashPegInQuoteEIP712(
        PegInQuote calldata quote
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(
            PEG_IN_QUOTE_TYPE_HASH,
            quote.liquidityProviderRskAddress,
            keccak256(abi.encode(_encodePart1(quote), _encodePart2(quote)))
        ));
    }

    /// @notice This function is used to get the hashStruct of a peg out quote using EIP712 specification
    /// @dev The hashStruct should be later combined with the domain separator to get the final hash
    /// @param quote The peg out quote to hash
    /// @return hashStruct The hash struct to be combined with the domain separator
    function hashPegOutQuoteEIP712(
        PegOutQuote calldata quote
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(
            PEG_OUT_QUOTE_TYPE_HASH,
            quote.lpRskAddress,
            keccak256(abi.encode(_encodePegOutPart1(quote), _encodePegOutPart2(quote)))
        ));
    }

    function encodeQuote(
        PegInQuote calldata quote
    ) external pure returns (bytes memory) {
        // Encode in two parts because abi.encode cannot take more than 12 parameters due to stack depth limits.
        return abi.encode(_encodePart1(quote), _encodePart2(quote));
    }

    function encodePegOutQuote(
        PegOutQuote calldata quote
    ) external pure returns (bytes memory) {
        // Encode in two parts because abi.encode cannot take more than 12 parameters due to stack depth limits.
        return abi.encode(_encodePegOutPart1(quote), _encodePegOutPart2(quote));
    }

    function _encodePart1(
        PegInQuote memory quote
    ) private pure returns (bytes memory) {
        return
            abi.encode(
                quote.chainId,
                quote.fedBtcAddress,
                quote.lbcAddress,
                quote.liquidityProviderRskAddress,
                quote.btcRefundAddress,
                quote.rskRefundAddress,
                quote.liquidityProviderBtcAddress,
                quote.callFee,
                quote.penaltyFee,
                quote.contractAddress
            );
    }

    function _encodePart2(
        PegInQuote memory quote
    ) private pure returns (bytes memory) {
        return
            abi.encode(
                quote.data,
                quote.gasLimit,
                quote.nonce,
                quote.value,
                quote.agreementTimestamp,
                quote.timeForDeposit,
                quote.callTime,
                quote.depositConfirmations,
                quote.callOnRegister,
                quote.gasFee
            );
    }

    function _encodePegOutPart1(
        PegOutQuote memory quote
    ) private pure returns (bytes memory) {
        return
            abi.encode(
                quote.chainId,
                quote.lbcAddress,
                quote.lpRskAddress,
                quote.btcRefundAddress,
                quote.rskRefundAddress,
                quote.lpBtcAddress,
                quote.callFee,
                quote.penaltyFee,
                quote.nonce,
                quote.depositAddress
            );
    }

    function _encodePegOutPart2(
        PegOutQuote memory quote
    ) private pure returns (bytes memory) {
        return
            abi.encode(
                quote.value,
                quote.agreementTimestamp,
                quote.depositDateLimit,
                quote.depositConfirmations,
                quote.transferConfirmations,
                quote.transferTime,
                quote.expireDate,
                quote.expireBlock,
                quote.gasFee
            );
    }
}

// node_modules/@openzeppelin/contracts/utils/math/SafeCast.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}

// node_modules/@rsksmart/btc-transaction-solidity-helper/contracts/BtcUtils.sol

/**
 * @title BtcUtils
 * @notice This library contains functionality to make easier to work with Bitcoin transactions in Solidity.
 * @notice This library is based in this document:
 *   https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
 */
library BtcUtils {
    uint8 private constant MAX_COMPACT_SIZE_LENGTH = 252;
    uint8 private constant MAX_BYTES_USED_FOR_COMPACT_SIZE = 8;

    uint private constant HASH160_SIZE = 20;
    uint private constant SHA256_SIZE = 32;
    uint private constant TAPROOT_PUBKEY_SIZE = 32;

    uint8 private constant OUTPOINT_SIZE = 36;
    uint8 private constant OUTPUT_VALUE_SIZE = 8;

    uint8 private constant PUBKEY_HASH_START = 3;
    bytes1 private constant PUBKEY_HASH_MAINNET_BYTE = 0x00;
    bytes1 private constant PUBKEY_HASH_TESTNET_BYTE = 0x6f;

    uint8 private constant SCRIPT_HASH_START = 2;
    bytes1 private constant SCRIPT_HASH_MAINNET_BYTE = 0x05;
    bytes1 private constant SCRIPT_HASH_TESTNET_BYTE = 0xc4;

    uint private constant BECH32_WORD_SIZE = 5;
    uint private constant BYTE_SIZE = 8;

    bytes1 private constant WITNESS_VERSION_0 = 0x00;
    bytes1 private constant WITNESS_VERSION_1 = 0x01;

    /**
     * @notice This struct contains the information of a tx output separated by fields
     * @notice Its just to have a structured representation of the output
     **/
    struct TxRawOutput {
        uint64 value;
        bytes pkScript;
        uint256 scriptSize;
        uint256 totalSize;
    }

    function version() external pure returns (string memory) {
        return "0.2.1";
    }

    /// @notice Parse a raw transaction to get an array of its outputs in a structured representation
    /// @param rawTx the raw transaction
    /// @return An array of `TxRawOutput` with the outputs of the transaction
    function getOutputs(bytes calldata rawTx) public pure returns (TxRawOutput[] memory) {
        uint currentPosition = 4;

        if (rawTx[4] == 0x00 && rawTx[5] == 0x01) { // if its segwit, skip marker and flag
            currentPosition = 6;
        }

        (uint64 inputCount, uint16 inputCountSize) = parseCompactSizeInt(currentPosition, rawTx);
        currentPosition += inputCountSize;

        uint64 scriptLarge;
        uint16 scriptLargeSize;
        for (uint64 i = 0; i < inputCount; i++) {
            currentPosition += OUTPOINT_SIZE;
            (scriptLarge, scriptLargeSize) = parseCompactSizeInt(currentPosition, rawTx);
            currentPosition += scriptLarge + scriptLargeSize + 4;
        }

        (uint64 outputCount, uint16 outputCountSize) = parseCompactSizeInt(currentPosition, rawTx);
        currentPosition += outputCountSize;

        TxRawOutput[] memory result = new TxRawOutput[](outputCount);
        for (uint i = 0; i < outputCount; i++) {
            result[i] = extractRawOutput(currentPosition, rawTx);
            currentPosition += result[i].totalSize;
        }
        return result;
    }

    function extractRawOutput(uint position, bytes memory rawTx) private pure returns (TxRawOutput memory) {
        TxRawOutput memory result = TxRawOutput(0, "", 0, 0);
        result.value = uint64(calculateLittleEndianFragment(position, position + OUTPUT_VALUE_SIZE, rawTx));
        position += OUTPUT_VALUE_SIZE;

        (uint64 scriptLength, uint16 scriptLengthSize) = parseCompactSizeInt(position, rawTx);
        position += scriptLengthSize;

        bytes memory pkScript = new bytes(scriptLength);
        for (uint64 i = 0; i < scriptLength; i++) {
            pkScript[i] = rawTx[position + i];
        }
        result.pkScript = pkScript;
        result.scriptSize = scriptLength;
        result.totalSize = OUTPUT_VALUE_SIZE + scriptLength + scriptLengthSize;
        return result;
    }

    /// @notice Parse a raw output script whose type is not known by the consumer. The function will
    /// return the corresponding address if the type of the script is supported or an error if not.
    /// For the addresses that are encoded with base58check the checksum bytes are not included in
    /// the resulting byte array
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @param mainnet if the address to generate is from mainnet or testnet
    /// @return The address bytes regarless of the output script type
    function outputScriptToAddress(bytes calldata outputScript, bool mainnet) public pure returns (bytes memory) {
        if (isP2PKHOutput(outputScript)) {
            return parsePayToPubKeyHash(outputScript, mainnet);
        }
        if (isP2SHOutput(outputScript)) {
            return parsePayToScriptHash(outputScript, mainnet);
        }
        if (isP2WPKHOutput(outputScript)) {
            return parsePayToWitnessPubKeyHash(outputScript);
        }
        if (isP2WSHOutput(outputScript)) {
            return parsePayToWitnessScriptHash(outputScript);
        }
        if (isP2TROutput(outputScript)) {
            return parsePayToTaproot(outputScript);
        }
        revert("Unsupported script type");
    }

    /// @notice Check if a raw output script is a pay-to-public-key-hash output
    /// @param pkScript the fragment of the raw transaction containing the raw output script
    /// @return Whether the script has a pay-to-public-key-hash output structure or not
    function isP2PKHOutput(bytes memory pkScript) public pure returns (bool) {
        return pkScript.length == 5 + HASH160_SIZE &&
            pkScript[0] == OpCodes.OP_DUP &&
            pkScript[1] == OpCodes.OP_HASH160 &&
            uint8(pkScript[2]) == HASH160_SIZE &&
            pkScript[23] == OpCodes.OP_EQUALVERIFY &&
            pkScript[24] ==  OpCodes.OP_CHECKSIG;
    }

    /// @notice Check if a raw output script is a pay-to-script-hash output
    /// @param pkScript the fragment of the raw transaction containing the raw output script
    /// @return Whether the script has a pay-to-script-hash output structure or not
    function isP2SHOutput(bytes memory pkScript) public pure returns (bool) {
        return pkScript.length == 3 + HASH160_SIZE &&
            pkScript[0] == OpCodes.OP_HASH160 &&
            uint8(pkScript[1]) == HASH160_SIZE &&
            pkScript[22] == OpCodes.OP_EQUAL;
    }

    /// @notice Check if a raw output script is a pay-to-witness-pubkey-hash output
    /// @param pkScript the fragment of the raw transaction containing the raw output script
    /// @return Whether the script has a pay-to-witness-pubkey-hash output structure or not
    function isP2WPKHOutput(bytes memory pkScript) public pure returns (bool) {
        return pkScript.length == 2 + HASH160_SIZE &&
            pkScript[0] == OpCodes.OP_0 &&
            uint8(pkScript[1]) == HASH160_SIZE;
    }

    /// @notice Check if a raw output script is a pay-to-witness-script-hash output
    /// @param pkScript the fragment of the raw transaction containing the raw output script
    /// @return Whether the script has a pay-to-witness-script-hash output structure or not
    function isP2WSHOutput(bytes memory pkScript) public pure returns (bool) {
        return pkScript.length == 2 + SHA256_SIZE &&
            pkScript[0] == OpCodes.OP_0 &&
            uint8(pkScript[1]) == SHA256_SIZE;
    }

    /// @notice Check if a raw output script is a pay-to-taproot output
    /// @notice Reference for implementation: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    /// @param pkScript the fragment of the raw transaction containing the raw output script
    /// @return Whether the script has a pay-to-taproot output structure or not
    function isP2TROutput(bytes memory pkScript) public pure returns (bool) {
        return pkScript.length == 2 + TAPROOT_PUBKEY_SIZE &&
            pkScript[0] == OpCodes.OP_1 &&
            uint8(pkScript[1]) == TAPROOT_PUBKEY_SIZE;
    }

    /// @notice Parse a raw pay-to-public-key-hash output script to get the corresponding address,
    /// the resulting byte array doesn't include the checksum bytes of the base58check encoding at
    /// the end
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @param mainnet if the address to generate is from mainnet or testnet
    /// @return The address generated using the receiver's public key hash
    function parsePayToPubKeyHash(bytes calldata outputScript, bool mainnet) public pure returns (bytes memory) {
        require(isP2PKHOutput(outputScript), "Script hasn't the required structure");

        bytes memory destinationAddress = new bytes(HASH160_SIZE + 1);
        for(uint8 i = PUBKEY_HASH_START; i < HASH160_SIZE + PUBKEY_HASH_START; i++) {
            destinationAddress[i - PUBKEY_HASH_START + 1] = outputScript[i];
        }

        destinationAddress[0] = mainnet? PUBKEY_HASH_MAINNET_BYTE : PUBKEY_HASH_TESTNET_BYTE;
        return destinationAddress;
    }

    /// @notice Parse a raw pay-to-script-hash output script to get the corresponding address,
    /// the resulting byte array doesn't include the checksum bytes of the base58check encoding at
    /// the end
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @param mainnet if the address to generate is from mainnet or testnet
    /// @return The address generated using the script hash
    function parsePayToScriptHash(bytes calldata outputScript, bool mainnet) public pure returns (bytes memory) {
        require(isP2SHOutput(outputScript), "Script hasn't the required structure");

        bytes memory destinationAddress = new bytes(HASH160_SIZE + 1);
        for(uint8 i = SCRIPT_HASH_START; i < HASH160_SIZE + SCRIPT_HASH_START; i++) {
            destinationAddress[i - SCRIPT_HASH_START + 1] = outputScript[i];
        }

        destinationAddress[0] = mainnet? SCRIPT_HASH_MAINNET_BYTE : SCRIPT_HASH_TESTNET_BYTE;
        return destinationAddress;
    }

    /// @notice Parse a raw pay-to-witness-pubkey-hash output script to get the corresponding address words,
    /// the resulting words are only the data part of the bech32 encoding and doesn't include the HRP
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @return The address bech32 words generated using the pubkey hash
    function parsePayToWitnessPubKeyHash(bytes calldata outputScript) public pure returns (bytes memory) {
        require(isP2WPKHOutput(outputScript), "Script hasn't the required structure");
        uint length = 1 + HASH160_SIZE;
        bytes memory result = new bytes(length);
        result[0] = WITNESS_VERSION_0;
        for (uint i = 1; i < length; i++) {
            result[i] = outputScript[i + 1];
        }
        return result;
    }

    /// @notice Parse a raw pay-to-witness-script-hash output script to get the corresponding address words,
    /// the resulting words are only the data part of the bech32 encoding and doesn't include the HRP
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @return The address bech32 words generated using the script hash
    function parsePayToWitnessScriptHash(bytes calldata outputScript) public pure returns (bytes memory) {
        require(isP2WSHOutput(outputScript), "Script hasn't the required structure");
        uint length = 1 + SHA256_SIZE;
        bytes memory result = new bytes(length);
        result[0] = WITNESS_VERSION_0;
        for (uint i = 1; i < length; i++) {
            result[i] = outputScript[i + 1];
        }
        return result;
    }

    /// @notice Parse a raw pay-to-taproot output script to get the corresponding address words,
    /// the resulting words are only the data part of the bech32m encoding and doesn't include the HRP
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @return The address bech32m words generated using the taproot pubkey hash
    function parsePayToTaproot(bytes calldata outputScript) public pure returns (bytes memory) {
        require(isP2TROutput(outputScript), "Script hasn't the required structure");
        uint length = 1 + TAPROOT_PUBKEY_SIZE;
        bytes memory result = new bytes(length);
        result[0] = WITNESS_VERSION_1;
        for (uint i = 1; i < length; i++) {
            result[i] = outputScript[i + 1];
        }
        return result;
    }

    /// @notice Parse a raw null-data output script to get its content
    /// @param outputScript the fragment of the raw transaction containing the raw output script
    /// @return The content embedded inside the script
    function parseNullDataScript(bytes calldata outputScript) public pure returns (bytes memory) {
        require(outputScript.length > 1,"Invalid size");
        require(outputScript[0] == OpCodes.OP_RETURN, "Not OP_RETURN");
        return outputScript[1:];
    }

    /// @notice Hash a bitcoin raw transaction to get its id (reversed double sha256)
    /// @param btcTx the transaction to hash
    /// @return The transaction id
    function hashBtcTx(bytes calldata btcTx) public pure returns (bytes32) {
        bytes memory doubleSha256 = abi.encodePacked(sha256(abi.encodePacked(sha256(btcTx))));
        bytes1 aux;
        for (uint i = 0; i < 16; i++) {
            aux = doubleSha256[i];
            doubleSha256[i] = doubleSha256[31 - i];
            doubleSha256[31 - i] = aux;
        }

        bytes32 result;
        assembly {
            result := mload(add(doubleSha256, 32))
        }
        return result;
    }

    /// @dev Gets the timestamp of a Bitcoin block header
    /// @param header The block header
    /// @return The timestamp of the block header
    function getBtcBlockTimestamp(bytes memory header) public pure returns (uint256) {
        // bitcoin header is 80 bytes and timestamp is 4 bytes from byte 68 to byte 71 (both inclusive)
        require(header.length == 80, "Invalid header length");

        return sliceUint32FromLSB(header, 68);
    }

    // bytes must have at least 28 bytes before the uint32
    function sliceUint32FromLSB(bytes memory bs, uint offset) private pure returns (uint32) {
        require(bs.length >= offset + 4, "Slicing out of range");

        return
        uint32(uint8(bs[offset])) |
        (uint32(uint8(bs[offset + 1])) << 8) |
        (uint32(uint8(bs[offset + 2])) << 16) |
        (uint32(uint8(bs[offset + 3])) << 24);
    }

    /// @notice Check if a pay-to-script-hash address belogs to a specific script, expects the address
    /// bytes to include the 4 checksum bytes at the end
    /// @param p2sh the pay-to-script-hash address
    /// @param script the script to check
    /// @param mainnet flag to specify if its a mainnet address
    /// @return Whether the address belongs to the script or not
    function validateP2SHAdress(bytes calldata p2sh, bytes calldata script, bool mainnet) public pure returns (bool) {
        return p2sh.length == 25 && keccak256(p2sh) ==  keccak256(getP2SHAddressFromScript(script, mainnet));
    }

    /// @notice Generate a pay-to-script-hash address from a script, the resulting byte array already contains
    /// the 4 checksum bytes at the end of it
    /// @param script the script to generate the address from
    /// @param mainnet flag to specify if the output should be a mainnet address
    /// @return The address generate from the script
    function getP2SHAddressFromScript(bytes calldata script, bool mainnet) public pure returns (bytes memory) {
        bytes20 scriptHash = ripemd160(abi.encodePacked(sha256(script)));
        bytes1 versionByte = mainnet ? SCRIPT_HASH_MAINNET_BYTE : SCRIPT_HASH_TESTNET_BYTE;
        bytes memory versionAndHash = bytes.concat(versionByte, scriptHash);
        bytes4 checksum = bytes4(sha256(abi.encodePacked(sha256(versionAndHash))));
        return bytes.concat(versionAndHash, checksum);
    }

    function parseCompactSizeInt(uint sizePosition, bytes memory array) private pure returns(uint64, uint16) {
        require(array.length > sizePosition, "Size position can't be bigger than array");
        uint8 maxSize = uint8(array[sizePosition]);
        if (maxSize == 0) {
            return (0, 1);
        } else if (maxSize <= MAX_COMPACT_SIZE_LENGTH) {
            return (maxSize, 1);
        }

        uint compactSizeBytes = 2 ** (maxSize - MAX_COMPACT_SIZE_LENGTH);
        require(compactSizeBytes <= MAX_BYTES_USED_FOR_COMPACT_SIZE, "unsupported compact size length");

        // the adition of 1 is because the first byte is the indicator of the size and its not part of the number
        uint64 result = uint64(
            calculateLittleEndianFragment(sizePosition + 1, sizePosition + compactSizeBytes + 1, array)
        );
        return (result, uint16(compactSizeBytes) + 1);
    }

    function calculateLittleEndianFragment(
        uint fragmentStart,
        uint fragmentEnd,
        bytes memory array
    ) private pure returns (uint) {
        require(
            fragmentStart < array.length && fragmentEnd < array.length,
            "Range can't be bigger than array"
        );
        uint result = 0;
        for (uint i = fragmentStart; i < fragmentEnd; i++) {
            result += uint8(array[i]) *  uint64(2 ** (8 * (i - (fragmentStart))));
        }
        return result;
    }
}

// node_modules/@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// node_modules/@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol

// OpenZeppelin Contracts (last updated v5.4.0) (access/extensions/IAccessControlDefaultAdminRules.sol)

/**
 * @dev External interface of AccessControlDefaultAdminRules declared to support ERC-165 detection.
 */
interface IAccessControlDefaultAdminRules is IAccessControl {
    /**
     * @dev The new default admin is not a valid default admin.
     */
    error AccessControlInvalidDefaultAdmin(address defaultAdmin);

    /**
     * @dev At least one of the following rules was violated:
     *
     * - The `DEFAULT_ADMIN_ROLE` must only be managed by itself.
     * - The `DEFAULT_ADMIN_ROLE` must only be held by one account at the time.
     * - Any `DEFAULT_ADMIN_ROLE` transfer must be in two delayed steps.
     */
    error AccessControlEnforcedDefaultAdminRules();

    /**
     * @dev The delay for transferring the default admin delay is enforced and
     * the operation must wait until `schedule`.
     *
     * NOTE: `schedule` can be 0 indicating there's no transfer scheduled.
     */
    error AccessControlEnforcedDefaultAdminDelay(uint48 schedule);

    /**
     * @dev Emitted when a {defaultAdmin} transfer is started, setting `newAdmin` as the next
     * address to become the {defaultAdmin} by calling {acceptDefaultAdminTransfer} only after `acceptSchedule`
     * passes.
     */
    event DefaultAdminTransferScheduled(address indexed newAdmin, uint48 acceptSchedule);

    /**
     * @dev Emitted when a {pendingDefaultAdmin} is reset if it was never accepted, regardless of its schedule.
     */
    event DefaultAdminTransferCanceled();

    /**
     * @dev Emitted when a {defaultAdminDelay} change is started, setting `newDelay` as the next
     * delay to be applied between default admin transfer after `effectSchedule` has passed.
     */
    event DefaultAdminDelayChangeScheduled(uint48 newDelay, uint48 effectSchedule);

    /**
     * @dev Emitted when a {pendingDefaultAdminDelay} is reset if its schedule didn't pass.
     */
    event DefaultAdminDelayChangeCanceled();

    /**
     * @dev Returns the address of the current `DEFAULT_ADMIN_ROLE` holder.
     */
    function defaultAdmin() external view returns (address);

    /**
     * @dev Returns a tuple of a `newAdmin` and an accept schedule.
     *
     * After the `schedule` passes, the `newAdmin` will be able to accept the {defaultAdmin} role
     * by calling {acceptDefaultAdminTransfer}, completing the role transfer.
     *
     * A zero value only in `acceptSchedule` indicates no pending admin transfer.
     *
     * NOTE: A zero address `newAdmin` means that {defaultAdmin} is being renounced.
     */
    function pendingDefaultAdmin() external view returns (address newAdmin, uint48 acceptSchedule);

    /**
     * @dev Returns the delay required to schedule the acceptance of a {defaultAdmin} transfer started.
     *
     * This delay will be added to the current timestamp when calling {beginDefaultAdminTransfer} to set
     * the acceptance schedule.
     *
     * NOTE: If a delay change has been scheduled, it will take effect as soon as the schedule passes, making this
     * function returns the new delay. See {changeDefaultAdminDelay}.
     */
    function defaultAdminDelay() external view returns (uint48);

    /**
     * @dev Returns a tuple of `newDelay` and an effect schedule.
     *
     * After the `schedule` passes, the `newDelay` will get into effect immediately for every
     * new {defaultAdmin} transfer started with {beginDefaultAdminTransfer}.
     *
     * A zero value only in `effectSchedule` indicates no pending delay change.
     *
     * NOTE: A zero value only for `newDelay` means that the next {defaultAdminDelay}
     * will be zero after the effect schedule.
     */
    function pendingDefaultAdminDelay() external view returns (uint48 newDelay, uint48 effectSchedule);

    /**
     * @dev Starts a {defaultAdmin} transfer by setting a {pendingDefaultAdmin} scheduled for acceptance
     * after the current timestamp plus a {defaultAdminDelay}.
     *
     * Requirements:
     *
     * - Only can be called by the current {defaultAdmin}.
     *
     * Emits a DefaultAdminRoleChangeStarted event.
     */
    function beginDefaultAdminTransfer(address newAdmin) external;

    /**
     * @dev Cancels a {defaultAdmin} transfer previously started with {beginDefaultAdminTransfer}.
     *
     * A {pendingDefaultAdmin} not yet accepted can also be cancelled with this function.
     *
     * Requirements:
     *
     * - Only can be called by the current {defaultAdmin}.
     *
     * May emit a DefaultAdminTransferCanceled event.
     */
    function cancelDefaultAdminTransfer() external;

    /**
     * @dev Completes a {defaultAdmin} transfer previously started with {beginDefaultAdminTransfer}.
     *
     * After calling the function:
     *
     * - `DEFAULT_ADMIN_ROLE` should be granted to the caller.
     * - `DEFAULT_ADMIN_ROLE` should be revoked from the previous holder.
     * - {pendingDefaultAdmin} should be reset to zero values.
     *
     * Requirements:
     *
     * - Only can be called by the {pendingDefaultAdmin}'s `newAdmin`.
     * - The {pendingDefaultAdmin}'s `acceptSchedule` should've passed.
     */
    function acceptDefaultAdminTransfer() external;

    /**
     * @dev Initiates a {defaultAdminDelay} update by setting a {pendingDefaultAdminDelay} scheduled for getting
     * into effect after the current timestamp plus a {defaultAdminDelay}.
     *
     * This function guarantees that any call to {beginDefaultAdminTransfer} done between the timestamp this
     * method is called and the {pendingDefaultAdminDelay} effect schedule will use the current {defaultAdminDelay}
     * set before calling.
     *
     * The {pendingDefaultAdminDelay}'s effect schedule is defined in a way that waiting until the schedule and then
     * calling {beginDefaultAdminTransfer} with the new delay will take at least the same as another {defaultAdmin}
     * complete transfer (including acceptance).
     *
     * The schedule is designed for two scenarios:
     *
     * - When the delay is changed for a larger one the schedule is `block.timestamp + newDelay` capped by
     * {defaultAdminDelayIncreaseWait}.
     * - When the delay is changed for a shorter one, the schedule is `block.timestamp + (current delay - new delay)`.
     *
     * A {pendingDefaultAdminDelay} that never got into effect will be canceled in favor of a new scheduled change.
     *
     * Requirements:
     *
     * - Only can be called by the current {defaultAdmin}.
     *
     * Emits a DefaultAdminDelayChangeScheduled event and may emit a DefaultAdminDelayChangeCanceled event.
     */
    function changeDefaultAdminDelay(uint48 newDelay) external;

    /**
     * @dev Cancels a scheduled {defaultAdminDelay} change.
     *
     * Requirements:
     *
     * - Only can be called by the current {defaultAdmin}.
     *
     * May emit a DefaultAdminDelayChangeCanceled event.
     */
    function rollbackDefaultAdminDelay() external;

    /**
     * @dev Maximum time in seconds for an increase to {defaultAdminDelay} (that is scheduled using {changeDefaultAdminDelay})
     * to take effect. Default to 5 days.
     *
     * When the {defaultAdminDelay} is scheduled to be increased, it goes into effect after the new delay has passed with
     * the purpose of giving enough time for reverting any accidental change (i.e. using milliseconds instead of seconds)
     * that may lock the contract. However, to avoid excessive schedules, the wait is capped by this function and it can
     * be overrode for a custom {defaultAdminDelay} increase scheduling.
     *
     * IMPORTANT: Make sure to add a reasonable amount of time while overriding this value, otherwise,
     * there's a risk of setting a high new delay that goes into effect almost immediately without the
     * possibility of human intervention in the case of an input error (eg. set milliseconds instead of seconds).
     */
    function defaultAdminDelayIncreaseWait() external view returns (uint48);
}

// node_modules/@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyGuardStorage {
        uint256 _status;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ReentrancyGuardStorageLocation = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _getReentrancyGuardStorage() private pure returns (ReentrancyGuardStorage storage $) {
        assembly {
            $.slot := ReentrancyGuardStorageLocation
        }
    }

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if ($._status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        $._status = ENTERED;
    }

    function _nonReentrantAfter() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        return $._status == ENTERED;
    }
}

// src/libraries/SignatureValidator.sol

library SignatureValidator {

    using ECDSA for bytes32;
    error IncorrectSignature(address expectedAddress, bytes32 usedHash, bytes signature);
    error SignatureCheckError(uint8 errorType, bytes32 errorArg);
    error ZeroAddress();
    /**
        @dev Verifies signature against address
        @param addr The signing address
        @param messageHash The hash of the signed message, the SignatureValidator won't perform any
        modification on the message. If this is used for EIP712, this contract expects it to be the
        final hash (domain hash + hashStruct)
        @param signature The signature containing v, r and s
        @return True if the signature is valid, false otherwise.
     */
    function verify(address addr, bytes32 messageHash, bytes memory signature) public pure returns (bool) {

        if (addr == address(0)) {
            revert ZeroAddress();
        }

        if (signature.length != 65) {
            revert IncorrectSignature(addr, messageHash, signature);
        }
        (address recovered, ECDSA.RecoverError err, bytes32 errorArg) = messageHash.tryRecover(signature);
        if (err != ECDSA.RecoverError.NoError) {
            revert SignatureCheckError(uint8(err), errorArg);
        }
        return recovered == addr;
    }

}

// node_modules/@openzeppelin/contracts/utils/math/SignedMath.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SignedMath.sol)

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, int256 a, int256 b) internal pure returns (int256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * int256(SafeCast.toUint(condition)));
        }
    }

    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // Formula from the "Bit Twiddling Hacks" by Sean Eron Anderson.
            // Since `n` is a signed integer, the generated bytecode will use the SAR opcode to perform the right shift,
            // taking advantage of the most significant (or "sign" bit) in two's complement representation.
            // This opcode adds new most significant bits set to the value of the previous most significant bit. As a result,
            // the mask will either be `bytes32(0)` (if n is positive) or `~bytes32(0)` (if n is negative).
            int256 mask = n >> 255;

            // A `bytes32(0)` mask leaves the input unchanged, while a `~bytes32(0)` mask complements it.
            return uint256((n + mask) ^ mask);
        }
    }
}

// node_modules/@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol

// OpenZeppelin Contracts (last updated v5.4.0) (utils/introspection/ERC165.sol)

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165Upgradeable is Initializable, IERC165 {
    function __ERC165_init() internal onlyInitializing {
    }

    function __ERC165_init_unchained() internal onlyInitializing {
    }
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// node_modules/@openzeppelin/contracts/utils/math/Math.sol

// OpenZeppelin Contracts (last updated v5.3.0) (utils/math/Math.sol)

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory byteArray) private pure returns (bool) {
        for (uint256 i = 0; i < byteArray.length; ++i) {
            if (byteArray[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the last 16 bytes.
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}

// src/interfaces/ICollateralManagement.sol

event CollateralManagementSet(address indexed oldAddress, address indexed newAddress);

/// @title Collateral Management interface
/// @notice This interface is used to expose the required functions to
/// provide the Flyover collateral management service.
/// This involves, slashing, resigning and registering processes.
interface ICollateralManagement is IPausable {

    /// @notice Emitted when the collateral is withdrawn
    /// @param caller The liquidity provider whose collateral was withdrawn (msg.sender)
    /// @param recipient The address that received the withdrawn collateral
    /// @param amount The amount of collateral withdrawn
    event WithdrawCollateral(address indexed caller, address indexed recipient, uint256 indexed amount);

    /// @notice Emitted when the liquidity provider resigns
    /// @param addr The address of the liquidity provider
    event Resigned(address indexed addr);

    /// @notice Emitted when the rewards are withdrawn by a punisher
    /// @param caller The punisher whose rewards were withdrawn (msg.sender)
    /// @param recipient The address that received the withdrawn rewards
    /// @param amount The amount of rewards withdrawn
    event RewardsWithdrawn(address indexed caller, address indexed recipient, uint256 indexed amount);

    /// @notice Emitted when the peg in collateral is added
    /// @param addr The address of the liquidity provider
    /// @param amount The amount of peg in collateral added
    event PegInCollateralAdded(address indexed addr, uint256 indexed amount);

    /// @notice Emitted when the peg out collateral is added
    /// @param addr The address of the liquidity provider
    /// @param amount The amount of peg out collateral added
    event PegOutCollateralAdded(address indexed addr, uint256 indexed amount);

    /// @notice Emitted when a liquidity provider is penalized by not behaving as expected
    /// @param liquidityProvider The address of the liquidity provider
    /// @param punisher The address of the punisher
    /// @param quoteHash The hash of the quote
    /// @param collateralType The type of collateral
    /// @param penalty The penalty amount for the liquidity provider
    /// @param reward The reward amount for the punisher
    event Penalized(
        address indexed liquidityProvider,
        address indexed punisher,
        bytes32 indexed quoteHash,
        Flyover.ProviderType collateralType,
        uint256 penalty,
        uint256 reward
    );

    /// @notice Emitted when a liquidity provider has already resigned
    /// @param from The address of the liquidity provider
    error AlreadyResigned(address from);

    /// @notice Emitted when a liquidity provider has not resigned yet
    /// @param from The address of the liquidity provider
    error NotResigned(address from);

    /// @notice Emitted when a liquidity provider has not resigned yet
    /// @param from The address of the liquidity provider
    /// @param resignationBlockNum The block number at which the liquidity provider resigned
    /// @param resignDelayInBlocks The delay in blocks before a liquidity provider can withdraw their collateral
    error ResignationDelayNotMet(address from, uint resignationBlockNum, uint resignDelayInBlocks);

    /// @notice Emitted when a liquidity provider tries to withdraw collateral but the withdrawal fails
    /// @param from The address of the liquidity provider
    /// @param amount The amount of collateral that was attempted to be withdrawn
    error WithdrawalFailed(address from, uint amount);

    /// @notice Emitted when a liquidity provider tries to withdraw collateral but has nothing to withdraw
    /// @param from The address of the liquidity provider
    error NothingToWithdraw(address from);

    /// @notice Emitted when reward percentage exceeds the allowed maximum
    /// @param maxRewardPercentage The maximum allowed reward percentage (basis points)
    /// @param passedRewardPercentage The provided reward percentage (basis points)
    error InvalidRewardPercentage(uint256 maxRewardPercentage, uint256 passedRewardPercentage);

    /// @notice Emitted when the minimum collateral is lower than the minimum allowed
    /// @param minCollateral The minimum collateral that was invalid
    error MinCollateralTooLow(uint256 minCollateral);

    /// @notice Adds peg in collateral to an account
    /// @param addr The address of the account
    /// @dev This function requires the COLLATERAL_ADDER role
    function addPegInCollateralTo(address addr) external payable;

    /// @notice Adds peg in collateral to the caller
    /// @dev This function can only be called by a liquidity provider. This means an
    /// account that has been registered by adding collateral with addPegInCollateralTo.
    /// This means the COLLATERAL_ADDER can't use this function unless they register themselves.
    function addPegInCollateral() external payable;

    /// @notice Slashes peg in collateral from a liquidity provider. The slashed amount
    /// is the penalty fee of the quote. Depending on the reward percentage, the punisher
    /// will receive a reward. The rest of the penalty fee remains in the contract.
    /// The punisher's reward is calculated using integer division (rounded down), and any
    /// remainder from this calculation stays in the protocol as additional penalties.
    /// @param punisher The address of the punisher
    /// @param quote The quote of the peg in collateral
    /// @param quoteHash The hash of the quote
    /// @dev This function requires the COLLATERAL_SLASHER role
    function slashPegInCollateral(
        address punisher,
        Quotes.PegInQuote calldata quote,
        bytes32 quoteHash
    ) external;

    /// @notice Adds peg out collateral to an account
    /// @param addr The address of the account
    /// @dev This function requires the COLLATERAL_ADDER role
    function addPegOutCollateralTo(address addr) external payable;

    /// @notice Adds peg out collateral to the caller
    /// @dev This function can only be called by a liquidity provider. This means an
    /// account that has been registered by adding collateral with addPegOutCollateralTo.
    /// This means the COLLATERAL_ADDER can't use this function unless they register themselves.
    function addPegOutCollateral() external payable;

    /// @notice Slashes peg out collateral from a liquidity provider. The slashed amount
    /// is the penalty fee of the quote. Depending on the reward percentage, the punisher
    /// will receive a reward. The reward is calculated using integer division (rounded
    /// down), and any remainder from this calculation remains in the contract as part
    /// of the protocol penalties.
    /// @param punisher The address of the punisher
    /// @param quote The quote of the peg out collateral
    /// @param quoteHash The hash of the quote
    /// @dev This function requires the COLLATERAL_SLASHER role
    function slashPegOutCollateral(
        address punisher,
        Quotes.PegOutQuote calldata quote,
        bytes32 quoteHash
    ) external;

    /// @notice Withdraws rewards from the contract. Sends to the caller. Use withdrawRewards(address payable to)
    /// to send to a different address (e.g. if the caller cannot receive ETH).
    function withdrawRewards() external;

    /// @notice Withdraws rewards from the contract to the given address. The caller must have
    /// accumulated rewards as a punisher. If the transfer fails, the call reverts and state is
    /// unchanged; the caller can retry with a different recipient (e.g. an EOA).
    /// @param to Must be non-zero; the address that will receive the withdrawn rewards.
    /// Reverts with Flyover.InvalidAddress(to) if to == address(0).
    function withdrawRewards(address payable to) external;

    /// @notice Withdraws collateral from the contract. Sends to the caller. Use withdrawCollateral(address payable to)
    /// to send to a different address (e.g. if the caller cannot receive ETH).
    function withdrawCollateral() external;

    /// @notice Withdraws collateral from the contract to the given address. Requires the caller
    /// to have resigned and the resignation delay to have passed. If the transfer fails, the call
    /// reverts and state is unchanged; the caller can retry with a different recipient.
    /// @param to Must be non-zero; the address that will receive the withdrawn collateral.
    /// Reverts with Flyover.InvalidAddress(to) if to == address(0).
    function withdrawCollateral(address payable to) external;

    /// @notice Resigns a liquidity provider
    function resign() external;

    /// @notice Gets the peg in collateral of an account
    /// @param addr The address of the account
    /// @return The amount of peg in collateral
    function getPegInCollateral(address addr) external view returns (uint256);

    /// @notice Gets the peg out collateral of an account
    /// @param addr The address of the account
    /// @return The amount of peg out collateral
    function getPegOutCollateral(address addr) external view returns (uint256);

    /// @notice Gets the block number at which a liquidity provider resigned
    function getResignationBlock(address addr) external view returns (uint256);

    /// @notice Gets the reward percentage from the penalty fee that the punisher will receive
    /// @return The reward percentage
    function getRewardPercentage() external view returns (uint256);

    /// @notice Gets the resignation delay in blocks
    /// @return The resignation delay in blocks
    function getResignDelayInBlocks() external view returns (uint256);

    /// @notice Gets the minimum collateral **per operation** required for a liquidity provider
    /// @return The minimum collateral required for a liquidity provider
    function getMinCollateral() external view returns (uint256);

    /// @notice Checks if an account is registered this means having added collateral to the
    /// contract and not having resigned
    /// @param providerType The type of provider
    /// @param addr The address of the account
    function isRegistered(Flyover.ProviderType providerType, address addr) external view returns (bool);

    /// @notice Checks if an account has sufficient collateral. This means having at least the minimum collateral
    /// for that operation and not having resigned.
    /// @param providerType The type of provider
    /// @param addr The address of the account
    function isCollateralSufficient(Flyover.ProviderType providerType, address addr) external view returns (bool);

    /// @notice Gets the rewards of an account accumulated from the punishments
    /// @param addr The address of the account
    /// @return The rewards of the account
    function getRewards(address addr) external view returns (uint256);

    /// @notice Gets the total penalties stored in the contract from the penalized liquidity providers
    /// @return The penalties amount
    function getPenalties() external view returns (uint256);
}

// src/interfaces/IPegIn.sol

/// @title PegIn interface
/// @notice This interface is used to expose the required functions to provide the Flyover peg in service
interface IPegIn is IPausable, IERC5267 {

    /// @notice The states of a peg in quote
    /// @dev The quote set to CALL_DONE when the callForUser function is called
    /// @dev The quote set to PROCESSED_QUOTE when the registerPegIn function is called
    /// @dev The quote set to UNPROCESSED_QUOTE when the the contract is not aware of the quote
    enum PegInStates { UNPROCESSED_QUOTE, CALL_DONE, PROCESSED_QUOTE }

    /// @notice Emitted when the balance of a liquidity provider increases
    /// @param dest The address of the liquidity provider
    /// @param amount The amount of the increase
    event BalanceIncrease(address indexed dest, uint256 indexed amount);

    /// @notice Emitted when the balance of a liquidity provider decreases
    /// @param dest The address of the liquidity provider
    /// @param amount The amount of the decrease
    event BalanceDecrease(address indexed dest, uint256 indexed amount);

    /// @notice Emitted when a liquidity provider withdraws funds
    /// @param from The address of the liquidity provider
    /// @param amount The amount of the withdrawal
    event Withdrawal(address indexed from, uint256 indexed amount);

    /// @notice Emitted when the bridge capacity is exceeded
    /// @param quoteHash The hash of the quote
    /// @param errorCode The error code returned by the bridge
    event BridgeCapExceeded(bytes32 indexed quoteHash, int256 indexed errorCode);

    /// @notice Emitted when a peg in is registered successfully
    /// @param quoteHash The hash of the quote
    /// @param transferredAmount The amount of the peg in
    event PegInRegistered(bytes32 indexed quoteHash, uint256 indexed transferredAmount);

    /// @notice Emitted when a user is refunded. This can happen if the liquidity provider
    /// fails to provide the service, if the user's payment was invalid, if the user requires
    /// to receive the change of their payment
    /// @param dest The address of the user
    /// @param quoteHash The hash of the quote
    /// @param amount The amount of the refund
    /// @param success Whether the refund was successful or not
    event Refund(address indexed dest, bytes32 indexed quoteHash, uint indexed amount, bool success);

    /// @notice Emitted when a call is made on behalf of the user
    /// @param from The address of the caller
    /// @param dest The address of the destination
    /// @param quoteHash The hash of the quote
    /// @param gasLimit The gas limit of the call
    /// @param value The value of the call
    /// @param data The data of the call
    /// @param success Whether the call was successful or not
    event CallForUser(
        address indexed from,
        address indexed dest,
        bytes32 indexed quoteHash,
        uint gasLimit,
        uint value,
        bytes data,
        bool success
    );

    /// @notice This error is emitted when the refund address is invalid
    /// @param refundAddress The refund address that is invalid
    error InvalidRefundAddress(bytes refundAddress);

    /// @notice This error is emitted when the amount is under the bridge's minimum amount
    /// @param amount The amount that is under the bridge's minimum
    error AmountUnderMinimum(uint256 amount);

    /// @notice This error is emitted when the quote has already been processed.
    /// This can happen if the callForUser or the registerPegIn functions are being
    /// called twice with the same quote
    /// @param quoteHash The hash of the quote
    error QuoteAlreadyProcessed(bytes32 quoteHash);

    /// @notice This error is emitted when the gas limit is insufficient to make the call
    /// on behalf of the user
    /// @param gasLeft The amount of gas left
    /// @param gasRequired The amount of gas required
    error InsufficientGas(uint256 gasLeft, uint256 gasRequired);

    /// @notice This error is emitted when the bridge needs more confirmations in order to
    /// be capable of registering the peg in
    error NotEnoughConfirmations();

    /// @notice This error is emitted when the bridge returns an unexpected error code
    /// @param errorCode The error code returned by the bridge
    error UnexpectedBridgeError(int256 errorCode);

    /// @notice This function is used to deposit funds into the contract to provide the
    /// peg in service
    /// @dev This function is only callable by a liquidity provider
    function deposit() external payable;

    /// @notice This function is used to make a peg in call on behalf of the user
    /// @dev This function is only callable by a liquidity provider. The value of the call
    /// will be added to the liquidity provider's balance.
    /// @param quote The quote of the peg in
    /// @return success Whether the call was successful or not
    function callForUser(Quotes.PegInQuote calldata quote) external payable returns (bool);

    /// @notice This function is used to withdraw funds from the contract
    /// @dev This function is only callable by a liquidity provider. They can partially
    /// withdraw their balance, this includes the profit made with the peg in service.
    /// @param amount The amount of the withdrawal
    function withdraw(uint256 amount) external;

    /// @notice This function is used to register a peg in in the bridge.
    /// It refunds the proper parties and penalizes the liquidity provider
    /// if applicable.
    /// @dev This function can be called by anyone
    /// @param quote The quote of the peg in
    /// @param signature The signature of the quoteHash by the liquidity provider
    /// @param btcRawTransaction The raw transaction of the peg in in the Bitcoin network
    /// @param partialMerkleTree The partial merkle tree proving the inclusion of the peg
    /// in transaction
    /// @param height The height of the peg in transaction
    /// @return registerResult The result of the registration. It can be:
    /// - A negative value: An error code returned by the bridge
    /// - A positive value: The amount of the peg in transaction
    function registerPegIn(
        Quotes.PegInQuote calldata quote,
        bytes calldata signature,
        bytes calldata btcRawTransaction,
        bytes calldata partialMerkleTree,
        uint256 height
    ) external returns (int256);

    /// @notice This function is used to get the balance of a liquidity provider
    /// @param addr The address of the liquidity provider
    /// @return balance The balance of the liquidity provider
    function getBalance(address addr) external view returns (uint256);

    /// @notice This function is used to get the status of a peg in quote
    /// @param quoteHash The hash of the quote
    /// @return status The status of the quote. Any value of the PegInStates enum
    function getQuoteStatus(bytes32 quoteHash) external view returns (PegInStates);

    /// @notice This function is used to validate the deposit address of a peg in quote
    /// @dev This function is used to validate the derivation address returned by the
    /// liquidity provider.
    /// @param quote The quote of the peg in
    /// @param depositAddress The deposit address to validate
    /// @return isValid Whether the deposit address is valid or not
    function validatePegInDepositAddress(
        Quotes.PegInQuote calldata quote,
        bytes calldata depositAddress
    ) external view returns (bool);

    /// @notice This view is used to get the hash of a peg in quote, this should be used as the
    /// single source of truth so all the involved parties can compute the quote hash in the same way
    /// @param quote The quote of the peg in
    /// @return quoteHash The hash of the quote
    function hashPegInQuote(Quotes.PegInQuote calldata quote) external view returns (bytes32);

    /// @notice This view is used to get the hash of a peg in quote using EIP712 specification
    /// @param quote The quote of the peg in
    /// @return hashStruct The hash struct to be combined with the domain separator
    function hashPegInQuoteEIP712(Quotes.PegInQuote calldata quote) external view returns (bytes32);

    /// @notice This function is used to get the minimum peg in amount allowed by the protocol
    /// @return minPegIn The minimum peg in amount
    function getMinPegIn() external view returns (uint256);
}

// src/EmergencyPause/EmergencyPause.sol

/* solhint-disable comprehensive-interface */

/// @notice Base contract for Flyover contracts that delegate pause state to a central PauseRegistry.
/// pauseStatus() and whenNotPaused read from the registry. Pause/unpause are done only on the registry.
/// Uses namespaced storage; no AccessControl (children that need roles inherit it separately).
abstract contract EmergencyPause is Initializable, IPausable {

    /// @custom:storage-location erc7201:rsk.flyover.EmergencyPause
    struct EmergencyPauseStorage {
        IPauseRegistry pauseRegistry;
    }

    // ERC-7201: keccak256(abi.encode(uint256(keccak256("rsk.flyover.EmergencyPause")) - 1)) &
    // ~bytes32(uint256(0xff))
    bytes32 private constant _EMERGENCY_PAUSE_STORAGE =
        0x9231f352ae2e78fc5cd04a185b8fc917dd5cf9947923b7000e25955769a61f00;

    /// @notice Modifier that reverts if the system is paused (reads from PauseRegistry)
    modifier whenNotPaused() {
        if (_getEmergencyPauseStorage().pauseRegistry.paused()) {
            revert Flyover.EnforcedPause();
        }
        _;
    }

    /// @inheritdoc IPausable
    function pauseStatus()
        public
        view
        virtual
        override(IPausable)
        returns (bool isPaused, string memory reason, uint64 since)
    {
        return _getEmergencyPauseStorage().pauseRegistry.pauseStatus();
    }

    /// @notice Returns the PauseRegistry used for pause state
    function pauseRegistry() public view returns (IPauseRegistry) {
        return _getEmergencyPauseStorage().pauseRegistry;
    }

    /// @notice Initialize EmergencyPause with reference to PauseRegistry
    /// @param pauseRegistry_ The central PauseRegistry
    // solhint-disable-next-line func-name-mixedcase
    function __EmergencyPause_init(IPauseRegistry pauseRegistry_)
        internal
        onlyInitializing
    {
        _getEmergencyPauseStorage().pauseRegistry = pauseRegistry_;
    }

    /// @notice Allows child contracts to update the pause registry (e.g. after upgrade or config change)
    /// @param pauseRegistry_ The new PauseRegistry
    function _setPauseRegistry(IPauseRegistry pauseRegistry_) internal {
        _getEmergencyPauseStorage().pauseRegistry = pauseRegistry_;
    }

    function _getEmergencyPauseStorage()
        private
        pure
        returns (EmergencyPauseStorage storage $)
    {
        assembly {
            $.slot := _EMERGENCY_PAUSE_STORAGE
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/Strings.sol

// OpenZeppelin Contracts (last updated v5.4.0) (utils/Strings.sol)

/**
 * @dev String operations.
 */
library Strings {
    using SafeCast for *;

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;
    uint256 private constant SPECIAL_CHARS_LOOKUP =
        (1 << 0x08) | // backspace
            (1 << 0x09) | // tab
            (1 << 0x0a) | // newline
            (1 << 0x0c) | // form feed
            (1 << 0x0d) | // carriage return
            (1 << 0x22) | // double quote
            (1 << 0x5c); // backslash

    /**
     * @dev The `value` string doesn't fit in the specified `length`.
     */
    error StringsInsufficientHexLength(uint256 value, uint256 length);

    /**
     * @dev The string being parsed contains characters that are not in scope of the given base.
     */
    error StringsInvalidChar();

    /**
     * @dev The string being parsed is not a properly formatted address.
     */
    error StringsInvalidAddressFormat();

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly ("memory-safe") {
                ptr := add(add(buffer, 0x20), length)
            }
            while (true) {
                ptr--;
                assembly ("memory-safe") {
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal
     * representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its checksummed ASCII `string` hexadecimal
     * representation, according to EIP-55.
     */
    function toChecksumHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = bytes(toHexString(addr));

        // hash the hex part of buffer (skip length + 2 bytes, length 40)
        uint256 hashValue;
        assembly ("memory-safe") {
            hashValue := shr(96, keccak256(add(buffer, 0x22), 40))
        }

        for (uint256 i = 41; i > 1; --i) {
            // possible values for buffer[i] are 48 (0) to 57 (9) and 97 (a) to 102 (f)
            if (hashValue & 0xf > 7 && uint8(buffer[i]) > 96) {
                // case shift by xoring with 0x20
                buffer[i] ^= 0x20;
            }
            hashValue >>= 4;
        }
        return string(buffer);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /**
     * @dev Parse a decimal string and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input) internal pure returns (uint256) {
        return parseUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        uint256 result = 0;
        for (uint256 i = begin; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 9) return (false, 0);
            result *= 10;
            result += chr;
        }
        return (true, result);
    }

    /**
     * @dev Parse a decimal string and returns the value as a `int256`.
     *
     * Requirements:
     * - The string must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input) internal pure returns (int256) {
        return parseInt(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseInt-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input, uint256 begin, uint256 end) internal pure returns (int256) {
        (bool success, int256 value) = tryParseInt(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseInt-string} that returns false if the parsing fails because of an invalid character or if
     * the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(string memory input) internal pure returns (bool success, int256 value) {
        return _tryParseIntUncheckedBounds(input, 0, bytes(input).length);
    }

    uint256 private constant ABS_MIN_INT256 = 2 ** 255;

    /**
     * @dev Variant of {parseInt-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character or if the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, int256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseIntUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseInt-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseIntUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, int256 value) {
        bytes memory buffer = bytes(input);

        // Check presence of a negative sign.
        bytes1 sign = begin == end ? bytes1(0) : bytes1(_unsafeReadBytesOffset(buffer, begin)); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        bool positiveSign = sign == bytes1("+");
        bool negativeSign = sign == bytes1("-");
        uint256 offset = (positiveSign || negativeSign).toUint();

        (bool absSuccess, uint256 absValue) = tryParseUint(input, begin + offset, end);

        if (absSuccess && absValue < ABS_MIN_INT256) {
            return (true, negativeSign ? -int256(absValue) : int256(absValue));
        } else if (absSuccess && negativeSign && absValue == ABS_MIN_INT256) {
            return (true, type(int256).min);
        } else return (false, 0);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input) internal pure returns (uint256) {
        return parseHexUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseHexUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseHexUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseHexUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string-uint256-uint256} that returns false if the parsing fails because of an
     * invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseHexUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseHexUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseHexUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        // skip 0x prefix if present
        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(buffer, begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 offset = hasPrefix.toUint() * 2;

        uint256 result = 0;
        for (uint256 i = begin + offset; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 15) return (false, 0);
            result *= 16;
            unchecked {
                // Multiplying by 16 is equivalent to a shift of 4 bits (with additional overflow check).
                // This guarantees that adding a value < 16 will not cause an overflow, hence the unchecked.
                result += chr;
            }
        }
        return (true, result);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as an `address`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input) internal pure returns (address) {
        return parseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input, uint256 begin, uint256 end) internal pure returns (address) {
        (bool success, address value) = tryParseAddress(input, begin, end);
        if (!success) revert StringsInvalidAddressFormat();
        return value;
    }

    /**
     * @dev Variant of {parseAddress-string} that returns false if the parsing fails because the input is not a properly
     * formatted address. See {parseAddress-string} requirements.
     */
    function tryParseAddress(string memory input) internal pure returns (bool success, address value) {
        return tryParseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string-uint256-uint256} that returns false if the parsing fails because input is not a properly
     * formatted address. See {parseAddress-string-uint256-uint256} requirements.
     */
    function tryParseAddress(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, address value) {
        if (end > bytes(input).length || begin > end) return (false, address(0));

        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(bytes(input), begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 expectedLength = 40 + hasPrefix.toUint() * 2;

        // check that input is the correct length
        if (end - begin == expectedLength) {
            // length guarantees that this does not overflow, and value is at most type(uint160).max
            (bool s, uint256 v) = _tryParseHexUintUncheckedBounds(input, begin, end);
            return (s, address(uint160(v)));
        } else {
            return (false, address(0));
        }
    }

    function _tryParseChr(bytes1 chr) private pure returns (uint8) {
        uint8 value = uint8(chr);

        // Try to parse `chr`:
        // - Case 1: [0-9]
        // - Case 2: [a-f]
        // - Case 3: [A-F]
        // - otherwise not supported
        unchecked {
            if (value > 47 && value < 58) value -= 48;
            else if (value > 96 && value < 103) value -= 87;
            else if (value > 64 && value < 71) value -= 55;
            else return type(uint8).max;
        }

        return value;
    }

    /**
     * @dev Escape special characters in JSON strings. This can be useful to prevent JSON injection in NFT metadata.
     *
     * WARNING: This function should only be used in double quoted JSON strings. Single quotes are not escaped.
     *
     * NOTE: This function escapes all unicode characters, and not just the ones in ranges defined in section 2.5 of
     * RFC-4627 (U+0000 to U+001F, U+0022 and U+005C). ECMAScript's `JSON.parse` does recover escaped unicode
     * characters that are not in this range, but other tooling may provide different results.
     */
    function escapeJSON(string memory input) internal pure returns (string memory) {
        bytes memory buffer = bytes(input);
        bytes memory output = new bytes(2 * buffer.length); // worst case scenario
        uint256 outputLength = 0;

        for (uint256 i; i < buffer.length; ++i) {
            bytes1 char = bytes1(_unsafeReadBytesOffset(buffer, i));
            if (((SPECIAL_CHARS_LOOKUP & (1 << uint8(char))) != 0)) {
                output[outputLength++] = "\\";
                if (char == 0x08) output[outputLength++] = "b";
                else if (char == 0x09) output[outputLength++] = "t";
                else if (char == 0x0a) output[outputLength++] = "n";
                else if (char == 0x0c) output[outputLength++] = "f";
                else if (char == 0x0d) output[outputLength++] = "r";
                else if (char == 0x5c) output[outputLength++] = "\\";
                else if (char == 0x22) {
                    // solhint-disable-next-line quotes
                    output[outputLength++] = '"';
                }
            } else {
                output[outputLength++] = char;
            }
        }
        // write the actual length and deallocate unused memory
        assembly ("memory-safe") {
            mstore(output, outputLength)
            mstore(0x40, add(output, shl(5, shr(5, add(outputLength, 63)))))
        }

        return string(output);
    }

    /**
     * @dev Reads a bytes32 from a bytes array without bounds checking.
     *
     * NOTE: making this function internal would mean it could be used with memory unsafe offset, and marking the
     * assembly block as such would prevent some optimizations.
     */
    function _unsafeReadBytesOffset(bytes memory buffer, uint256 offset) private pure returns (bytes32 value) {
        // This is not memory safe in the general case, but all calls to this private function are within bounds.
        assembly ("memory-safe") {
            value := mload(add(add(buffer, 0x20), offset))
        }
    }
}

// node_modules/@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.4.0) (access/AccessControl.sol)

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControlUpgradeable is Initializable, ContextUpgradeable, IAccessControl, ERC165Upgradeable {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /// @custom:storage-location erc7201:openzeppelin.storage.AccessControl
    struct AccessControlStorage {
        mapping(bytes32 role => RoleData) _roles;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControl")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlStorageLocation = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    function _getAccessControlStorage() private pure returns (AccessControlStorage storage $) {
        assembly {
            $.slot := AccessControlStorageLocation
        }
    }

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    function __AccessControl_init() internal onlyInitializing {
    }

    function __AccessControl_init_unchained() internal onlyInitializing {
    }
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        return $._roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        return $._roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        AccessControlStorage storage $ = _getAccessControlStorage();
        bytes32 previousAdminRole = getRoleAdmin(role);
        $._roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        if (!hasRole(role, account)) {
            $._roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        AccessControlStorage storage $ = _getAccessControlStorage();
        if (hasRole(role, account)) {
            $._roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol

// OpenZeppelin Contracts (last updated v5.3.0) (utils/cryptography/MessageHashUtils.sol)

/**
 * @dev Signature message hash utilities for producing digests to be consumed by {ECDSA} recovery or signing.
 *
 * The library provides methods for generating a hash of a message that conforms to the
 * https://eips.ethereum.org/EIPS/eip-191[ERC-191] and https://eips.ethereum.org/EIPS/eip-712[EIP 712]
 * specifications.
 */
library MessageHashUtils {
    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing a bytes32 `messageHash` with
     * `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
     * hash signed when using the https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
     * keccak256, although any bytes32 value can be safely used because the final digest will
     * be re-hashed.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }

    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing an arbitrary `message` with
     * `"\x19Ethereum Signed Message:\n" + len(message)` and hashing the result. It corresponds with the
     * hash signed when using the https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes memory message) internal pure returns (bytes32) {
        return
            keccak256(bytes.concat("\x19Ethereum Signed Message:\n", bytes(Strings.toString(message.length)), message));
    }

    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x00` (data with intended validator).
     *
     * The digest is calculated by prefixing an arbitrary `data` with `"\x19\x00"` and the intended
     * `validator` address. Then hashing the result.
     *
     * See {ECDSA-recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"19_00", validator, data));
    }

    /**
     * @dev Variant of {toDataWithIntendedValidatorHash-address-bytes} optimized for cases where `data` is a bytes32.
     */
    function toDataWithIntendedValidatorHash(
        address validator,
        bytes32 messageHash
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            mstore(0x00, hex"19_00")
            mstore(0x02, shl(96, validator))
            mstore(0x16, messageHash)
            digest := keccak256(0x00, 0x36)
        }
    }

    /**
     * @dev Returns the keccak256 digest of an EIP-712 typed data (ERC-191 version `0x01`).
     *
     * The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them with
     * `\x19\x01` and hashing the result. It corresponds to the hash signed by the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of EIP-712.
     *
     * See {ECDSA-recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}

// node_modules/@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol

// OpenZeppelin Contracts (last updated v5.4.0) (utils/cryptography/EIP712.sol)

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP-712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding scheme specified in the EIP requires a domain separator and a hash of the typed structured data, whose
 * encoding is very generic and therefore its implementation in Solidity is not feasible, thus this contract
 * does not implement the encoding itself. Protocols need to implement the type-specific encoding they need in order to
 * produce the hash of their typed data using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP-712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 *
 * NOTE: The upgradeable version of this contract does not use an immutable cache and recomputes the domain separator
 * each time {_domainSeparatorV4} is called. That is cheaper than accessing a cached version in cold storage.
 */
abstract contract EIP712Upgradeable is Initializable, IERC5267 {
    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @custom:storage-location erc7201:openzeppelin.storage.EIP712
    struct EIP712Storage {
        /// @custom:oz-renamed-from _HASHED_NAME
        bytes32 _hashedName;
        /// @custom:oz-renamed-from _HASHED_VERSION
        bytes32 _hashedVersion;

        string _name;
        string _version;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.EIP712")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant EIP712StorageLocation = 0xa16a46d94261c7517cc8ff89f61c0ce93598e3c849801011dee649a6a557d100;

    function _getEIP712Storage() private pure returns (EIP712Storage storage $) {
        assembly {
            $.slot := EIP712StorageLocation
        }
    }

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP-712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    function __EIP712_init(string memory name, string memory version) internal onlyInitializing {
        __EIP712_init_unchained(name, version);
    }

    function __EIP712_init_unchained(string memory name, string memory version) internal onlyInitializing {
        EIP712Storage storage $ = _getEIP712Storage();
        $._name = name;
        $._version = version;

        // Reset prior values in storage if upgrading
        $._hashedName = 0;
        $._hashedVersion = 0;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _EIP712NameHash(), _EIP712VersionHash(), block.chainid, address(this)));
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    /// @inheritdoc IERC5267
    function eip712Domain()
        public
        view
        virtual
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        EIP712Storage storage $ = _getEIP712Storage();
        // If the hashed name and version in storage are non-zero, the contract hasn't been properly initialized
        // and the EIP712 domain is not reliable, as it will be missing name and version.
        require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized");

        return (
            hex"0f", // 01111
            _EIP712Name(),
            _EIP712Version(),
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    /**
     * @dev The name parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712Name() internal view virtual returns (string memory) {
        EIP712Storage storage $ = _getEIP712Storage();
        return $._name;
    }

    /**
     * @dev The version parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712Version() internal view virtual returns (string memory) {
        EIP712Storage storage $ = _getEIP712Storage();
        return $._version;
    }

    /**
     * @dev The hash of the name parameter for the EIP712 domain.
     *
     * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Name` instead.
     */
    function _EIP712NameHash() internal view returns (bytes32) {
        EIP712Storage storage $ = _getEIP712Storage();
        string memory name = _EIP712Name();
        if (bytes(name).length > 0) {
            return keccak256(bytes(name));
        } else {
            // If the name is empty, the contract may have been upgraded without initializing the new storage.
            // We return the name hash in storage if non-zero, otherwise we assume the name is empty by design.
            bytes32 hashedName = $._hashedName;
            if (hashedName != 0) {
                return hashedName;
            } else {
                return keccak256("");
            }
        }
    }

    /**
     * @dev The hash of the version parameter for the EIP712 domain.
     *
     * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Version` instead.
     */
    function _EIP712VersionHash() internal view returns (bytes32) {
        EIP712Storage storage $ = _getEIP712Storage();
        string memory version = _EIP712Version();
        if (bytes(version).length > 0) {
            return keccak256(bytes(version));
        } else {
            // If the version is empty, the contract may have been upgraded without initializing the new storage.
            // We return the version hash in storage if non-zero, otherwise we assume the version is empty by design.
            bytes32 hashedVersion = $._hashedVersion;
            if (hashedVersion != 0) {
                return hashedVersion;
            } else {
                return keccak256("");
            }
        }
    }
}

// node_modules/@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol

// OpenZeppelin Contracts (last updated v5.4.0) (access/extensions/AccessControlDefaultAdminRules.sol)

/**
 * @dev Extension of {AccessControl} that allows specifying special rules to manage
 * the `DEFAULT_ADMIN_ROLE` holder, which is a sensitive role with special permissions
 * over other roles that may potentially have privileged rights in the system.
 *
 * If a specific role doesn't have an admin role assigned, the holder of the
 * `DEFAULT_ADMIN_ROLE` will have the ability to grant it and revoke it.
 *
 * This contract implements the following risk mitigations on top of {AccessControl}:
 *
 * * Only one account holds the `DEFAULT_ADMIN_ROLE` since deployment until it's potentially renounced.
 * * Enforces a 2-step process to transfer the `DEFAULT_ADMIN_ROLE` to another account.
 * * Enforces a configurable delay between the two steps, with the ability to cancel before the transfer is accepted.
 * * The delay can be changed by scheduling, see {changeDefaultAdminDelay}.
 * * Role transfers must wait at least one block after scheduling before it can be accepted.
 * * It is not possible to use another role to manage the `DEFAULT_ADMIN_ROLE`.
 *
 * Example usage:
 *
 * ```solidity
 * contract MyToken is AccessControlDefaultAdminRules {
 *   constructor() AccessControlDefaultAdminRules(
 *     3 days,
 *     msg.sender // Explicit initial `DEFAULT_ADMIN_ROLE` holder
 *    ) {}
 * }
 * ```
 */
abstract contract AccessControlDefaultAdminRulesUpgradeable is Initializable, IAccessControlDefaultAdminRules, IERC5313, AccessControlUpgradeable {
    /// @custom:storage-location erc7201:openzeppelin.storage.AccessControlDefaultAdminRules
    struct AccessControlDefaultAdminRulesStorage {
        // pending admin pair read/written together frequently
        address _pendingDefaultAdmin;
        uint48 _pendingDefaultAdminSchedule; // 0 == unset

        uint48 _currentDelay;
        address _currentDefaultAdmin;

        // pending delay pair read/written together frequently
        uint48 _pendingDelay;
        uint48 _pendingDelaySchedule; // 0 == unset
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControlDefaultAdminRules")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlDefaultAdminRulesStorageLocation = 0xeef3dac4538c82c8ace4063ab0acd2d15cdb5883aa1dff7c2673abb3d8698400;

    function _getAccessControlDefaultAdminRulesStorage() private pure returns (AccessControlDefaultAdminRulesStorage storage $) {
        assembly {
            $.slot := AccessControlDefaultAdminRulesStorageLocation
        }
    }

    /**
     * @dev Sets the initial values for {defaultAdminDelay} and {defaultAdmin} address.
     */
    function __AccessControlDefaultAdminRules_init(uint48 initialDelay, address initialDefaultAdmin) internal onlyInitializing {
        __AccessControlDefaultAdminRules_init_unchained(initialDelay, initialDefaultAdmin);
    }

    function __AccessControlDefaultAdminRules_init_unchained(uint48 initialDelay, address initialDefaultAdmin) internal onlyInitializing {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        if (initialDefaultAdmin == address(0)) {
            revert AccessControlInvalidDefaultAdmin(address(0));
        }
        $._currentDelay = initialDelay;
        _grantRole(DEFAULT_ADMIN_ROLE, initialDefaultAdmin);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlDefaultAdminRules).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IERC5313
    function owner() public view virtual returns (address) {
        return defaultAdmin();
    }

    ///
    /// Override AccessControl role management
    ///

    /**
     * @dev See {AccessControl-grantRole}. Reverts for `DEFAULT_ADMIN_ROLE`.
     */
    function grantRole(bytes32 role, address account) public virtual override(AccessControlUpgradeable, IAccessControl) {
        if (role == DEFAULT_ADMIN_ROLE) {
            revert AccessControlEnforcedDefaultAdminRules();
        }
        super.grantRole(role, account);
    }

    /**
     * @dev See {AccessControl-revokeRole}. Reverts for `DEFAULT_ADMIN_ROLE`.
     */
    function revokeRole(bytes32 role, address account) public virtual override(AccessControlUpgradeable, IAccessControl) {
        if (role == DEFAULT_ADMIN_ROLE) {
            revert AccessControlEnforcedDefaultAdminRules();
        }
        super.revokeRole(role, account);
    }

    /**
     * @dev See {AccessControl-renounceRole}.
     *
     * For the `DEFAULT_ADMIN_ROLE`, it only allows renouncing in two steps by first calling
     * {beginDefaultAdminTransfer} to the `address(0)`, so it's required that the {pendingDefaultAdmin} schedule
     * has also passed when calling this function.
     *
     * After its execution, it will not be possible to call `onlyRole(DEFAULT_ADMIN_ROLE)` functions.
     *
     * NOTE: Renouncing `DEFAULT_ADMIN_ROLE` will leave the contract without a {defaultAdmin},
     * thereby disabling any functionality that is only available for it, and the possibility of reassigning a
     * non-administrated role.
     */
    function renounceRole(bytes32 role, address account) public virtual override(AccessControlUpgradeable, IAccessControl) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        if (role == DEFAULT_ADMIN_ROLE && account == defaultAdmin()) {
            (address newDefaultAdmin, uint48 schedule) = pendingDefaultAdmin();
            if (newDefaultAdmin != address(0) || !_isScheduleSet(schedule) || !_hasSchedulePassed(schedule)) {
                revert AccessControlEnforcedDefaultAdminDelay(schedule);
            }
            delete $._pendingDefaultAdminSchedule;
        }
        super.renounceRole(role, account);
    }

    /**
     * @dev See {AccessControl-_grantRole}.
     *
     * For `DEFAULT_ADMIN_ROLE`, it only allows granting if there isn't already a {defaultAdmin} or if the
     * role has been previously renounced.
     *
     * NOTE: Exposing this function through another mechanism may make the `DEFAULT_ADMIN_ROLE`
     * assignable again. Make sure to guarantee this is the expected behavior in your implementation.
     */
    function _grantRole(bytes32 role, address account) internal virtual override returns (bool) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        if (role == DEFAULT_ADMIN_ROLE) {
            if (defaultAdmin() != address(0)) {
                revert AccessControlEnforcedDefaultAdminRules();
            }
            $._currentDefaultAdmin = account;
        }
        return super._grantRole(role, account);
    }

    /// @inheritdoc AccessControlUpgradeable
    function _revokeRole(bytes32 role, address account) internal virtual override returns (bool) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        if (role == DEFAULT_ADMIN_ROLE && account == defaultAdmin()) {
            delete $._currentDefaultAdmin;
        }
        return super._revokeRole(role, account);
    }

    /**
     * @dev See {AccessControl-_setRoleAdmin}. Reverts for `DEFAULT_ADMIN_ROLE`.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual override {
        if (role == DEFAULT_ADMIN_ROLE) {
            revert AccessControlEnforcedDefaultAdminRules();
        }
        super._setRoleAdmin(role, adminRole);
    }

    ///
    /// AccessControlDefaultAdminRules accessors
    ///

    /// @inheritdoc IAccessControlDefaultAdminRules
    function defaultAdmin() public view virtual returns (address) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        return $._currentDefaultAdmin;
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function pendingDefaultAdmin() public view virtual returns (address newAdmin, uint48 schedule) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        return ($._pendingDefaultAdmin, $._pendingDefaultAdminSchedule);
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function defaultAdminDelay() public view virtual returns (uint48) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        uint48 schedule = $._pendingDelaySchedule;
        return (_isScheduleSet(schedule) && _hasSchedulePassed(schedule)) ? $._pendingDelay : $._currentDelay;
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function pendingDefaultAdminDelay() public view virtual returns (uint48 newDelay, uint48 schedule) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        schedule = $._pendingDelaySchedule;
        return (_isScheduleSet(schedule) && !_hasSchedulePassed(schedule)) ? ($._pendingDelay, schedule) : (0, 0);
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function defaultAdminDelayIncreaseWait() public view virtual returns (uint48) {
        return 5 days;
    }

    ///
    /// AccessControlDefaultAdminRules public and internal setters for defaultAdmin/pendingDefaultAdmin
    ///

    /// @inheritdoc IAccessControlDefaultAdminRules
    function beginDefaultAdminTransfer(address newAdmin) public virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        _beginDefaultAdminTransfer(newAdmin);
    }

    /**
     * @dev See {beginDefaultAdminTransfer}.
     *
     * Internal function without access restriction.
     */
    function _beginDefaultAdminTransfer(address newAdmin) internal virtual {
        uint48 newSchedule = SafeCast.toUint48(block.timestamp) + defaultAdminDelay();
        _setPendingDefaultAdmin(newAdmin, newSchedule);
        emit DefaultAdminTransferScheduled(newAdmin, newSchedule);
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function cancelDefaultAdminTransfer() public virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        _cancelDefaultAdminTransfer();
    }

    /**
     * @dev See {cancelDefaultAdminTransfer}.
     *
     * Internal function without access restriction.
     */
    function _cancelDefaultAdminTransfer() internal virtual {
        _setPendingDefaultAdmin(address(0), 0);
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function acceptDefaultAdminTransfer() public virtual {
        (address newDefaultAdmin, ) = pendingDefaultAdmin();
        if (_msgSender() != newDefaultAdmin) {
            // Enforce newDefaultAdmin explicit acceptance.
            revert AccessControlInvalidDefaultAdmin(_msgSender());
        }
        _acceptDefaultAdminTransfer();
    }

    /**
     * @dev See {acceptDefaultAdminTransfer}.
     *
     * Internal function without access restriction.
     */
    function _acceptDefaultAdminTransfer() internal virtual {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        (address newAdmin, uint48 schedule) = pendingDefaultAdmin();
        if (!_isScheduleSet(schedule) || !_hasSchedulePassed(schedule)) {
            revert AccessControlEnforcedDefaultAdminDelay(schedule);
        }
        _revokeRole(DEFAULT_ADMIN_ROLE, defaultAdmin());
        _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        delete $._pendingDefaultAdmin;
        delete $._pendingDefaultAdminSchedule;
    }

    ///
    /// AccessControlDefaultAdminRules public and internal setters for defaultAdminDelay/pendingDefaultAdminDelay
    ///

    /// @inheritdoc IAccessControlDefaultAdminRules
    function changeDefaultAdminDelay(uint48 newDelay) public virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        _changeDefaultAdminDelay(newDelay);
    }

    /**
     * @dev See {changeDefaultAdminDelay}.
     *
     * Internal function without access restriction.
     */
    function _changeDefaultAdminDelay(uint48 newDelay) internal virtual {
        uint48 newSchedule = SafeCast.toUint48(block.timestamp) + _delayChangeWait(newDelay);
        _setPendingDelay(newDelay, newSchedule);
        emit DefaultAdminDelayChangeScheduled(newDelay, newSchedule);
    }

    /// @inheritdoc IAccessControlDefaultAdminRules
    function rollbackDefaultAdminDelay() public virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        _rollbackDefaultAdminDelay();
    }

    /**
     * @dev See {rollbackDefaultAdminDelay}.
     *
     * Internal function without access restriction.
     */
    function _rollbackDefaultAdminDelay() internal virtual {
        _setPendingDelay(0, 0);
    }

    /**
     * @dev Returns the amount of seconds to wait after the `newDelay` will
     * become the new {defaultAdminDelay}.
     *
     * The value returned guarantees that if the delay is reduced, it will go into effect
     * after a wait that honors the previously set delay.
     *
     * See {defaultAdminDelayIncreaseWait}.
     */
    function _delayChangeWait(uint48 newDelay) internal view virtual returns (uint48) {
        uint48 currentDelay = defaultAdminDelay();

        // When increasing the delay, we schedule the delay change to occur after a period of "new delay" has passed, up
        // to a maximum given by defaultAdminDelayIncreaseWait, by default 5 days. For example, if increasing from 1 day
        // to 3 days, the new delay will come into effect after 3 days. If increasing from 1 day to 10 days, the new
        // delay will come into effect after 5 days. The 5 day wait period is intended to be able to fix an error like
        // using milliseconds instead of seconds.
        //
        // When decreasing the delay, we wait the difference between "current delay" and "new delay". This guarantees
        // that an admin transfer cannot be made faster than "current delay" at the time the delay change is scheduled.
        // For example, if decreasing from 10 days to 3 days, the new delay will come into effect after 7 days.
        return
            newDelay > currentDelay
                ? uint48(Math.min(newDelay, defaultAdminDelayIncreaseWait())) // no need to safecast, both inputs are uint48
                : currentDelay - newDelay;
    }

    ///
    /// Private setters
    ///

    /**
     * @dev Setter of the tuple for pending admin and its schedule.
     *
     * May emit a DefaultAdminTransferCanceled event.
     */
    function _setPendingDefaultAdmin(address newAdmin, uint48 newSchedule) private {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        (, uint48 oldSchedule) = pendingDefaultAdmin();

        $._pendingDefaultAdmin = newAdmin;
        $._pendingDefaultAdminSchedule = newSchedule;

        // An `oldSchedule` from `pendingDefaultAdmin()` is only set if it hasn't been accepted.
        if (_isScheduleSet(oldSchedule)) {
            // Emit for implicit cancellations when another default admin was scheduled.
            emit DefaultAdminTransferCanceled();
        }
    }

    /**
     * @dev Setter of the tuple for pending delay and its schedule.
     *
     * May emit a DefaultAdminDelayChangeCanceled event.
     */
    function _setPendingDelay(uint48 newDelay, uint48 newSchedule) private {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        uint48 oldSchedule = $._pendingDelaySchedule;

        if (_isScheduleSet(oldSchedule)) {
            if (_hasSchedulePassed(oldSchedule)) {
                // Materialize a virtual delay
                $._currentDelay = $._pendingDelay;
            } else {
                // Emit for implicit cancellations when another delay was scheduled.
                emit DefaultAdminDelayChangeCanceled();
            }
        }

        $._pendingDelay = newDelay;
        $._pendingDelaySchedule = newSchedule;
    }

    ///
    /// Private helpers
    ///

    /**
     * @dev Defines if an `schedule` is considered set. For consistency purposes.
     */
    function _isScheduleSet(uint48 schedule) private pure returns (bool) {
        return schedule != 0;
    }

    /**
     * @dev Defines if an `schedule` is considered passed. For consistency purposes.
     */
    function _hasSchedulePassed(uint48 schedule) private view returns (bool) {
        return schedule < block.timestamp;
    }
}

// src/PegInContract.sol

/// @title PegIn
/// @notice This contract is used to handle the peg in of the Bitcoin network to the Rootstock network
/// @dev All non pure/view functions in this contract should be marked as nonReentrant
/// @author Rootstock Labs
contract PegInContract is
    AccessControlDefaultAdminRulesUpgradeable,
    EmergencyPause,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable,
    IPegIn
{
    /// @notice This struct is used to store the information of a call on behalf of the user
    /// @param timestamp The timestamp of the call
    /// @param success Whether the call was successful or not
    struct Registry {
        uint256 timestamp;
        bool success;
    }

    /// @notice The version of the contract
    string constant public VERSION = "1.0.0";
    /// @notice The name of the contract (used for EIP712)
    string constant public NAME = "PegInContract";
    Flyover.ProviderType constant private _PEG_TYPE = Flyover.ProviderType.PegIn;
    uint256 constant private _REFUND_ADDRESS_LENGTH = 21;

    uint256 constant private _MAX_CALL_GAS_COST = 35000;
    uint256 constant private _MAX_REFUND_GAS_LIMIT = 2300;

    int256 constant private _BRIDGE_UNPROCESSABLE_TX_VALIDATIONS_ERROR = -303;
    int256 constant private _BRIDGE_REFUNDED_USER_ERROR_CODE = -100;
    int256 constant private _BRIDGE_REFUNDED_LP_ERROR_CODE = -200;

    IBridge private _bridge;
    ICollateralManagement private _collateralManagement;

    mapping(address => uint256) private _balances;
    mapping(bytes32 => PegInStates) private _processedQuotes;
    mapping(bytes32 => Registry) private _callRegistry;

    uint256 private _minPegIn;
    bool private _mainnet;
    /// @notice The dust threshold for the peg in. If the difference between the amount paid and the amount required
    /// is more than this value, the difference goes back to the user's wallet
    uint256 public dustThreshold;

    /// @notice Emitted when the dust threshold is set
    /// @param oldThreshold The old dust threshold
    /// @param newThreshold The new dust threshold
    event DustThresholdSet(uint256 indexed oldThreshold, uint256 indexed newThreshold);

    /// @notice Emitted when the minimum peg in amount is set
    /// @param oldMinPegIn The old minimum peg in amount
    /// @param newMinPegIn The new minimum peg in amount
    event MinPegInSet(uint256 indexed oldMinPegIn, uint256 indexed newMinPegIn);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // solhint-disable-next-line comprehensive-interface
    receive() external payable {
        if (msg.sender != address(_bridge)) {
            revert Flyover.PaymentNotAllowed();
        }
    }

    /// @notice This function is used to initialize the contract
    /// @param defaultAdmin the default admin of the contract
    /// @param bridge the address of the Rootstock bridge
    /// @param dustThreshold_ the dust threshold for the peg in
    /// @param minPegIn the minimum peg in amount supported by the bridge
    /// @param collateralManagement the address of the Collateral Management contract
    /// @param mainnet whether the contract is on the mainnet or not
    /// @param pauseRegistry the central PauseRegistry for pause state
    // solhint-disable-next-line comprehensive-interface
    function initialize(
        address defaultAdmin,
        address payable bridge,
        uint256 dustThreshold_,
        uint256 minPegIn,
        address collateralManagement,
        bool mainnet,
        IPauseRegistry pauseRegistry
    ) external initializer {
        if (collateralManagement.code.length == 0) revert Flyover.NoContract(collateralManagement);
        if (address(pauseRegistry).code.length == 0) revert Flyover.NoContract(address(pauseRegistry));
        __AccessControlDefaultAdminRules_init(0, defaultAdmin);
        __ReentrancyGuard_init();
        __EIP712_init(NAME, VERSION);
        __EmergencyPause_init(pauseRegistry);
        _bridge = IBridge(bridge);
        _collateralManagement = ICollateralManagement(collateralManagement);
        _mainnet = mainnet;
        dustThreshold = dustThreshold_;
        _minPegIn = minPegIn;
    }

    /// @notice This function is used to set the collateral management contract
    /// @param collateralManagement the address of the Collateral Management contract
    /// @dev This function is only callable by the owner of the contract
    // solhint-disable-next-line comprehensive-interface
    function setCollateralManagement(address collateralManagement) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (collateralManagement.code.length == 0) revert Flyover.NoContract(collateralManagement);
        emit CollateralManagementSet(address(_collateralManagement), collateralManagement);
        _collateralManagement = ICollateralManagement(collateralManagement);
    }

    /// @notice This function is used to set the dust threshold
    /// @param threshold the new dust threshold
    /// @dev This function is only callable by the owner of the contract
    // solhint-disable-next-line comprehensive-interface
    function setDustThreshold(uint256 threshold) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        emit DustThresholdSet(dustThreshold, threshold);
        dustThreshold = threshold;
    }

    /// @notice This function is used to set the minimum peg in amount
    /// @param minPegIn the new minimum peg in amount
    /// @dev This function is only callable by the owner of the contract
    // solhint-disable-next-line comprehensive-interface
    function setMinPegIn(uint256 minPegIn) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        emit MinPegInSet(_minPegIn, minPegIn);
        _minPegIn = minPegIn;
    }

    /// @inheritdoc IPegIn
    function deposit() external payable nonReentrant whenNotPaused override {
        if(!_collateralManagement.isRegistered(_PEG_TYPE, msg.sender)) {
            revert Flyover.ProviderNotRegistered(msg.sender);
        }
        _increaseBalance(msg.sender, msg.value);
    }

    /// @inheritdoc IPegIn
    function withdraw(uint256 amount) external nonReentrant override  {
        uint256 balance = _balances[msg.sender];
        if (balance < amount) {
            revert Flyover.NoBalance(amount, balance);
        }
        _decreaseBalance(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
        (bool success, bytes memory reason) = msg.sender.call{value: amount}("");
        if (!success) {
            revert Flyover.PaymentFailed(msg.sender, amount, reason);
        }
    }

    /// @inheritdoc IPegIn
    function callForUser(
        Quotes.PegInQuote calldata quote
    ) external payable nonReentrant override returns (bool) {
        if(!_collateralManagement.isRegistered(_PEG_TYPE, msg.sender)) {
            revert Flyover.ProviderNotRegistered(msg.sender);
        }
        if (quote.liquidityProviderRskAddress != msg.sender) {
            revert Flyover.InvalidSender(quote.liquidityProviderRskAddress, msg.sender);
        }
        uint256 newBalance = _balances[quote.liquidityProviderRskAddress] + msg.value;
        if (newBalance < quote.value) {
            revert Flyover.InsufficientAmount(newBalance, quote.value);
        }

        bytes32 quoteHash = _hashPegInQuote(quote);
        if (_processedQuotes[quoteHash] != PegInStates.UNPROCESSED_QUOTE) {
            revert QuoteAlreadyProcessed(quoteHash);
        }

        _increaseBalance(quote.liquidityProviderRskAddress, msg.value);

        // This check ensures that the call cannot be performed with less gas than the agreed amount
        if (gasleft() < quote.gasLimit + _MAX_CALL_GAS_COST) {
            revert InsufficientGas(gasleft(), quote.gasLimit + _MAX_CALL_GAS_COST);
        }
        (bool success,) = quote.contractAddress.call{
            gas: quote.gasLimit,
            value: quote.value
        }(quote.data);

        _callRegistry[quoteHash].timestamp = block.timestamp;
        _processedQuotes[quoteHash] = PegInStates.CALL_DONE;

        if (success) {
            _callRegistry[quoteHash].success = true;
            _decreaseBalance(quote.liquidityProviderRskAddress, quote.value);
        }

        emit CallForUser(
            msg.sender,
            quote.contractAddress,
            quoteHash,
            quote.gasLimit,
            quote.value,
            quote.data,
            success
        );
        return success;
    }

    /// @inheritdoc IPegIn
    function registerPegIn(
        Quotes.PegInQuote calldata quote,
        bytes calldata signature,
        bytes calldata btcRawTransaction,
        bytes calldata partialMerkleTree,
        uint256 height
    ) external nonReentrant override returns (int256) {
        bytes32 quoteHash = _hashPegInQuote(quote);
        _validateRegisterParams(quote, quoteHash, height, signature);
        int256 registerResult = _registerBridge(quote, btcRawTransaction, partialMerkleTree, height, quoteHash);

        bool btcRefunded = registerResult == _BRIDGE_REFUNDED_USER_ERROR_CODE ||
            registerResult == _BRIDGE_REFUNDED_LP_ERROR_CODE;
        if (registerResult == _BRIDGE_UNPROCESSABLE_TX_VALIDATIONS_ERROR) {
            revert NotEnoughConfirmations();
        } else if (!btcRefunded && registerResult < 1) {
            revert UnexpectedBridgeError(registerResult);
        }

        Registry memory callRegistry = _callRegistry[quoteHash];
        delete _callRegistry[quoteHash];
        if (_shouldPenalize(quote, registerResult, callRegistry.timestamp, height)) {
            _collateralManagement.slashPegInCollateral(msg.sender, quote, quoteHash);
        }
        if (btcRefunded) {
            _processedQuotes[quoteHash] = PegInStates.PROCESSED_QUOTE;
            emit BridgeCapExceeded(quoteHash, registerResult);
            return registerResult;
        }

        // the amount is safely assumed positive because it's already been validated there's
        // no (negative) error code being returned by the bridge.
        uint256 transferredAmount = uint256(registerResult);
        Quotes.checkAgreedAmount(quote, transferredAmount);

        _processedQuotes[quoteHash] = PegInStates.PROCESSED_QUOTE;
        emit PegInRegistered(quoteHash, transferredAmount);
        if (callRegistry.timestamp > 0) {
            _registerCallDone(quote, quoteHash, callRegistry.success, transferredAmount);
        } else {
            _registerCallNotDone(quote, quoteHash, transferredAmount);
        }
        return registerResult;
    }

    /// @inheritdoc IPegIn
    function validatePegInDepositAddress(
        Quotes.PegInQuote calldata quote,
        bytes calldata depositAddress
    ) external view override returns (bool) {
        bytes32 derivationValue = keccak256(
            bytes.concat(
                _hashPegInQuote(quote),
                quote.btcRefundAddress,
                bytes20(quote.lbcAddress),
                quote.liquidityProviderBtcAddress
            )
        );
        bytes memory flyoverRedeemScript = bytes.concat(
            OpCodes.OP_PUSHBYTES_32,
            derivationValue,
            OpCodes.OP_DROP,
            _bridge.getActivePowpegRedeemScript()
        );
        bytes memory segwitScript = bytes.concat(OpCodes.OP_0, OpCodes.OP_PUSHBYTES_32, sha256(flyoverRedeemScript));
        return BtcUtils.validateP2SHAdress(depositAddress, segwitScript, _mainnet);
    }

    /// @inheritdoc IPegIn
    function getMinPegIn() external view override returns (uint256) {
        return _minPegIn;
    }

    /// @inheritdoc IPegIn
    function getBalance(address addr) external view override returns (uint256) {
        if (_reentrancyGuardEntered()) revert ReentrancyGuardReentrantCall();
        return _balances[addr];
    }

    /// @inheritdoc IPegIn
    function hashPegInQuote(Quotes.PegInQuote calldata quote) external view override returns (bytes32) {
        return _hashPegInQuote(quote);
    }

    /// @inheritdoc IPegIn
    function hashPegInQuoteEIP712(Quotes.PegInQuote calldata quote) external view override returns (bytes32) {
        return _hashPegInQuoteEIP712(quote);
    }

    /// @inheritdoc IPegIn
    function getQuoteStatus(bytes32 quoteHash) external view override returns (PegInStates) {
        if (_reentrancyGuardEntered()) revert ReentrancyGuardReentrantCall();
        return _processedQuotes[quoteHash];
    }

    /// @notice This function is used to increase the balance of an account
    /// @dev This function must remain private. Any exposure can lead to a loss of funds.
    /// It is responsibility of the caller to ensure that the account is a liquidity provider
    /// @param dest The address of account
    /// @param amount The amount of balance to increase
    function _increaseBalance(address dest, uint256 amount) private {
        if (amount > 0) {
            _balances[dest] += amount;
            emit BalanceIncrease(dest, amount);
        }
    }

    /// @notice This function is used to decrease the balance of an account
    /// @dev This function must remain private. Any exposure can lead to a loss of funds.
    /// It is responsibility of the caller to ensure that the account is a liquidity provider
    /// @param dest The address of account
    /// @param amount The amount of balance to decrease
    function _decreaseBalance(address dest, uint256 amount) private {
        if (amount > 0) {
            _balances[dest] -= amount;
            emit BalanceDecrease(dest, amount);
        }
    }

    /// @notice This function is used to register the peg in into the bridge
    /// @param quote The quote of the peg in
    /// @param btcRawTransaction The raw transaction of the peg in in the Bitcoin network,
    /// without the witness data
    /// @param partialMerkleTree The partial merkle tree proving the inclusion of the peg
    /// in transaction
    /// @param height The height of the peg in transaction
    /// @param derivationHash The hash of the quote used to derive the deposit address
    /// @return registerResult The result of the registration. It can be:
    /// - A negative value: An error code returned by the bridge
    /// - A positive value: The amount of the peg in transaction
    function _registerBridge(
        Quotes.PegInQuote memory quote,
        bytes memory btcRawTransaction,
        bytes memory partialMerkleTree,
        uint256 height,
        bytes32 derivationHash
    ) private returns (int256) {
        Registry memory callRegistry = _callRegistry[derivationHash];
        return _bridge.registerFastBridgeBtcTransaction(
            btcRawTransaction,
            height,
            partialMerkleTree,
            derivationHash,
            quote.btcRefundAddress,
            payable(this),
            quote.liquidityProviderBtcAddress,
            callRegistry.timestamp > 0 && callRegistry.success
        );
    }

    /// @notice This function is used by the registerPegIn function to handle the scenarios
    /// where the liquidity provider has already called the callForUser function
    /// @dev This function makes an external call, therefore it might be exposed to a reentrancy attack,
    /// the caller must have the nonReentrant modifier or any kind of reentrancy protection. Not all the
    /// modifications to the state can be done before the call as some of them depend on the result of the
    /// call itself
    /// @param quote The quote of the peg in
    /// @param quoteHash The hash of the quote
    /// @param callSuccessful Whether the call on behalf of the user was successful or not
    /// @param transferredAmount The amount of the peg in transaction
    function _registerCallDone(
        Quotes.PegInQuote calldata quote,
        bytes32 quoteHash,
        bool callSuccessful,
        uint256 transferredAmount
    ) private {
        uint refundAmount;
        if (callSuccessful) {
            refundAmount = _min(transferredAmount, quote.value + quote.callFee + quote.gasFee);
        } else {
            refundAmount = _min(transferredAmount, quote.callFee + quote.gasFee);
        }
        _increaseBalance(quote.liquidityProviderRskAddress, refundAmount);

        uint remainingAmount = transferredAmount - refundAmount;
        if (remainingAmount > dustThreshold) {
            // refund rskRefundAddress, if remaining amount greater than dust
            (bool success,) = quote.rskRefundAddress.call{
                gas: _MAX_REFUND_GAS_LIMIT,
                value: remainingAmount
            }("");

            emit Refund(
                quote.rskRefundAddress,
                quoteHash,
                remainingAmount,
                success
            );

            if (!success) {
                // transfer funds to LP instead, if for some reason transfer to rskRefundAddress was unsuccessful
                _increaseBalance(quote.liquidityProviderRskAddress, remainingAmount);
            }
        }
    }

    /// @notice This function is used by the registerPegIn function to handle the scenarios
    /// where the liquidity provider has not called the callForUser function
    /// @dev This function makes an external call, therefore it might be exposed to a reentrancy attack,
    /// the caller must have the nonReentrant modifier or any kind of reentrancy protection. Not all the
    /// modifications to the state can be done before the call as some of them depend on the result of the
    /// call itself
    /// @param quote The quote of the peg in
    /// @param quoteHash The hash of the quote
    /// @param transferredAmount The amount of the peg in transaction
    function _registerCallNotDone(
        Quotes.PegInQuote calldata quote,
        bytes32 quoteHash,
        uint256 transferredAmount
    ) private {
        uint refundAmount = transferredAmount;

        if (quote.callOnRegister && refundAmount >= quote.value) { // solhint-disable-line gas-strict-inequalities
            (bool callSuccess,) = quote.contractAddress.call{
                gas: quote.gasLimit,
                value: quote.value
            }(quote.data);

            emit CallForUser(
                msg.sender,
                quote.contractAddress,
                quoteHash,
                quote.gasLimit,
                quote.value,
                quote.data,
                callSuccess
            );

            if (callSuccess) {
                refundAmount -= quote.value;
            }
        }
        if (refundAmount > dustThreshold) {
            // refund rskRefundAddress, if refund amount greater than dust
            (bool success,) = quote.rskRefundAddress.call{
                gas: _MAX_REFUND_GAS_LIMIT,
                value: refundAmount
            }("");
            emit Refund(
                quote.rskRefundAddress,
                quoteHash,
                refundAmount,
                success
            );
            if (!success) {
                // transfer funds to user instead, if for some reason transfer to rskRefundAddress was unsuccessful
                _increaseBalance(quote.rskRefundAddress, refundAmount);
            }
        }
    }

    /// @notice This function is used to validate the parameters of the registerPegIn function
    /// @dev The validations include:
    /// - If the quote was already registered
    /// - If the signature provided by the liquidity provider is valid
    /// - If the height is supported by the Rootstock bridge
    /// @param quote The quote of the peg in
    /// @param quoteHash The hash of the quote
    /// @param height The height of the peg in transaction
    /// @param signature The signature of the quoteHash by the liquidity provider
    function _validateRegisterParams(
        Quotes.PegInQuote calldata quote,
        bytes32 quoteHash,
        uint256 height,
        bytes calldata signature
    ) private view {
        if (_processedQuotes[quoteHash] == PegInStates.PROCESSED_QUOTE) {
            revert QuoteAlreadyProcessed(quoteHash);
        }
        bytes32 eip712hash = _hashPegInQuoteEIP712(quote);
        if (!SignatureValidator.verify(quote.liquidityProviderRskAddress, eip712hash, signature)) {
            revert SignatureValidator.IncorrectSignature(quote.liquidityProviderRskAddress, eip712hash, signature);
        }
        // the actual type in the RSKj node source code is a java int which is equivalent to int32
        if (height > uint256(int(type(int32).max)) - 1) {
            revert Flyover.Overflow(uint256(int(type(int32).max)));
        }
    }

    /// @notice This function is used to hash a peg in quote
    /// @dev The function also validates the following:
    /// - The quote belongs to this contract
    /// - The quote destination is not the bridge contract
    /// - The quote BTC refund address is valid
    /// - The quote liquidity provider BTC address is valid
    /// - The quote total amount is greater than the bridge minimum peg in amount
    /// - The sum of the timestamp values is not greater than the maximum uint32 value
    /// @param quote The peg in quote
    /// @return quoteHash The hash of the quote
    function _hashPegInQuote(Quotes.PegInQuote calldata quote) private view returns (bytes32) {
        _validatePegInQuote(quote);
        return keccak256(Quotes.encodeQuote(quote));
    }

    /// @notice This function is used to hash a peg in quote using EIP712 specification
    /// @dev The function also validates the following:
    /// - The quote belongs to this contract
    /// - The quote destination is not the bridge contract
    /// - The quote BTC refund address is valid
    /// - The quote liquidity provider BTC address is valid
    /// - The quote total amount is greater than the bridge minimum peg in amount
    /// - The sum of the timestamp values is not greater than the maximum uint32 value
    /// @param quote The peg in quote
    /// @return quoteHash The hash struct to be combined with the domain separator
    function _hashPegInQuoteEIP712(Quotes.PegInQuote calldata quote) private view returns (bytes32) {
        _validatePegInQuote(quote);
        return _hashTypedDataV4(Quotes.hashPegInQuoteEIP712(quote));
    }

    function _validatePegInQuote(Quotes.PegInQuote calldata quote) private view {
        if (quote.chainId != block.chainid) {
            revert Flyover.InvalidChainId(block.chainid, quote.chainId);
        }
        if (address(this) != quote.lbcAddress) {
            revert Flyover.IncorrectContract(address(this), quote.lbcAddress);
        }
        if (
            address(_bridge) == quote.contractAddress ||
            address(this) == quote.contractAddress ||
            address(0) == quote.contractAddress ||
            address(_collateralManagement) == quote.contractAddress
        ) {
            revert Flyover.NoContract(quote.contractAddress);
        }
        if (
            quote.btcRefundAddress.length != _REFUND_ADDRESS_LENGTH ||
            !_isValidBtcPrefix(quote.btcRefundAddress[0])
        ) {
            revert InvalidRefundAddress(quote.btcRefundAddress);
        }
        if (
            quote.liquidityProviderBtcAddress.length != _REFUND_ADDRESS_LENGTH ||
            !_isValidBtcPrefix(quote.liquidityProviderBtcAddress[0])
        ) {
            revert InvalidRefundAddress(quote.liquidityProviderBtcAddress);
        }
        uint256 total = quote.value + quote.callFee + quote.gasFee;
        if (total < _minPegIn) {
            revert AmountUnderMinimum(_minPegIn);
        }
        if (type(uint32).max < uint64(quote.agreementTimestamp) + uint64(quote.timeForDeposit)) {
            revert Flyover.Overflow(type(uint32).max);
        }
    }

    /// @notice This function is used to check if the prefix of a btc address is valid
    /// @param prefix The prefix of the address
    /// @return isValid Whether the prefix is valid or not
    function _isValidBtcPrefix(bytes1 prefix) private view returns (bool) {
        return _mainnet ?
            prefix == 0x00 || prefix == 0x05 : // p2pkh and p2sh mainnet
            prefix == 0x6f || prefix == 0xc4; // p2pkh and p2sh testnet
    }

    /// @notice This function is used to determine if the liquidity provider should be penalized
    /// @param quote The peg in quote
    /// @param amount The amount of the peg in transaction
    /// @param callTimestamp The timestamp of the call on behalf of the user
    /// @param height The height of the peg in transaction
    /// @return shouldPenalize Whether the liquidity provider should be penalized or not
    function _shouldPenalize(
        Quotes.PegInQuote calldata quote,
        int256 amount,
        uint256 callTimestamp,
        uint256 height
    ) private view returns (bool) {
        // do not penalize if deposit amount is insufficient
        uint256 quoteTotal = quote.value + quote.callFee + quote.gasFee;
        if (amount > 0 && uint256(amount) < quoteTotal) {
            return false;
        }

        bytes memory firstConfirmationHeader = _bridge.getBtcBlockchainBlockHeaderByHeight(height);
        if (firstConfirmationHeader.length < 1) revert Flyover.EmptyBlockHeader(bytes32(height));

        uint256 firstConfirmationTimestamp = BtcUtils.getBtcBlockTimestamp(
            firstConfirmationHeader
        );

        // do not penalize if deposit was not made on time
        uint256 timeLimit = quote.agreementTimestamp + quote.timeForDeposit;
        if (firstConfirmationTimestamp > timeLimit) {
            return false;
        }

        // penalize if call was not made
        if (callTimestamp == 0) {
            return true;
        }

        bytes memory nConfirmationsHeader = _bridge.getBtcBlockchainBlockHeaderByHeight(
            height + quote.depositConfirmations - 1
        );
        if (nConfirmationsHeader.length < 1) revert Flyover.EmptyBlockHeader(bytes32(height));
        uint256 nConfirmationsTimestamp = BtcUtils.getBtcBlockTimestamp(
            nConfirmationsHeader
        );

        // penalize if the call was not made on time
        if (callTimestamp > nConfirmationsTimestamp + quote.callTime) {
            return true;
        }

        return false;
    }

    /// @dev Utility function to return the minimum of two uint256 values
    function _min(uint a, uint b) private pure returns (uint) {
        return a < b ? a : b;
    }
}

