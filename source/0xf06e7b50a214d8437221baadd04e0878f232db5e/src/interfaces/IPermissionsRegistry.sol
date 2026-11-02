// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title IPermissionsRegistry
 * @notice External interface for the PermissionsRegistry: a self-sovereign on-chain registry where any
 *         address can grant or revoke arbitrary `bytes32` permissions to delegatees on its own behalf.
 */
interface IPermissionsRegistry {
    // --------------------------------------------------------------------- //
    // Errors                                                                //
    // --------------------------------------------------------------------- //

    error ZeroAddress();
    error SelfDelegationNotAllowed();
    error PermissionAlreadyGranted(address owner, address delegatee, bytes32 permission);
    error PermissionNotGranted(address owner, address delegatee, bytes32 permission);

    // --------------------------------------------------------------------- //
    // Events                                                                //
    // --------------------------------------------------------------------- //

    event PermissionGranted(address indexed owner, address indexed delegatee, bytes32 indexed permission);
    event PermissionRevoked(address indexed owner, address indexed delegatee, bytes32 indexed permission);

    // --------------------------------------------------------------------- //
    // Owner self-service                                                    //
    // --------------------------------------------------------------------- //

    function addManager(address delegatee) external;
    function revokeManager(address delegatee) external;
    function grantPermission(address delegatee, bytes32 permission) external;
    function revokePermission(address delegatee, bytes32 permission) external;

    // --------------------------------------------------------------------- //
    // Admin                                                                 //
    // --------------------------------------------------------------------- //

    function pause() external;
    function unpause() external;

    // --------------------------------------------------------------------- //
    // Views                                                                 //
    // --------------------------------------------------------------------- //

    function hasPermission(address owner, address delegatee, bytes32 permission) external view returns (bool);
    function isManager(address owner, address delegatee) external view returns (bool);
}
