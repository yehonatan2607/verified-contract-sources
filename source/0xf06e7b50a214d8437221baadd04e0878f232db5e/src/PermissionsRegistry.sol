// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import { IPermissionsRegistry } from "./interfaces/IPermissionsRegistry.sol";

/**
 * @title PermissionsRegistry
 * @notice Self-sovereign on-chain registry for arbitrary `(owner, delegatee, permission)` grants.
 *         Anyone can grant or revoke any `bytes32` permission to a delegatee on their own behalf.
 *         Permission ids are purely conventional — consumers (e.g. downstream contracts) define
 *         their own constants and only honor the ids they recognize. Duplicate grants and
 *         revokes of non-existent permissions revert. The contract
 *         owner can pause grants/revokes and upgrade the implementation, but cannot mutate any
 *         user's delegatee state.
 */
contract PermissionsRegistry is
    IPermissionsRegistry,
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable
{
    bytes32 public constant MANAGER_PERMISSION = keccak256("MANAGER_PERMISSION");

    mapping(address owner => mapping(address delegatee => mapping(bytes32 permission => bool))) private _granted;

    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) public initializer {
        if (_owner == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __Ownable_init(_owner);
        __Pausable_init();
    }

    // --------------------------------------------------------------------- //
    // Owner self-service                                                    //
    // --------------------------------------------------------------------- //

    function addManager(address _delegatee) external whenNotPaused {
        _grant(msg.sender, _delegatee, MANAGER_PERMISSION);
    }

    function revokeManager(address _delegatee) external whenNotPaused {
        _revoke(msg.sender, _delegatee, MANAGER_PERMISSION);
    }

    function grantPermission(address _delegatee, bytes32 _permission) external whenNotPaused {
        _grant(msg.sender, _delegatee, _permission);
    }

    function revokePermission(address _delegatee, bytes32 _permission) external whenNotPaused {
        _revoke(msg.sender, _delegatee, _permission);
    }

    // --------------------------------------------------------------------- //
    // Admin                                                                 //
    // --------------------------------------------------------------------- //

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // --------------------------------------------------------------------- //
    // Internal helpers                                                      //
    // --------------------------------------------------------------------- //

    function _grant(address _owner, address _delegatee, bytes32 _permission) internal {
        if (_delegatee == address(0)) revert ZeroAddress();
        if (_delegatee == _owner) revert SelfDelegationNotAllowed();
        if (_granted[_owner][_delegatee][_permission]) {
            revert PermissionAlreadyGranted(_owner, _delegatee, _permission);
        }

        _granted[_owner][_delegatee][_permission] = true;
        emit PermissionGranted(_owner, _delegatee, _permission);
    }

    function _revoke(address _owner, address _delegatee, bytes32 _permission) internal {
        if (!_granted[_owner][_delegatee][_permission]) {
            revert PermissionNotGranted(_owner, _delegatee, _permission);
        }

        _granted[_owner][_delegatee][_permission] = false;
        emit PermissionRevoked(_owner, _delegatee, _permission);
    }

    function _authorizeUpgrade(address _newImplementation) internal override onlyOwner { }

    // --------------------------------------------------------------------- //
    // Views                                                                 //
    // --------------------------------------------------------------------- //

    function hasPermission(address _owner, address _delegatee, bytes32 _permission) external view returns (bool) {
        return _granted[_owner][_delegatee][_permission];
    }

    function isManager(address _owner, address _delegatee) external view returns (bool) {
        return _granted[_owner][_delegatee][MANAGER_PERMISSION];
    }
}
