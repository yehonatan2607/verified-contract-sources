// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

interface IVetoMachine {
    /**
     * @notice get the veto percentage performed for the given proposal and a voting round
     * @param proposalAddress The address of the proposal to get the veto percentage for
     * @param round The voting round to get the veto percentage for
     * @return The veto percentage for the given proposal and round
     */
    function getVetoPct(address proposalAddress, uint256 round) external view returns (uint256);
}
