// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {IERC20} from "@openzeppelin/contracts-ethereum-package/contracts/token/ERC20/IERC20.sol";
import {IRegistry} from "@moc/periphery/contracts/IRegistry.sol";
import {RegistryConstants} from "@moc/periphery/contracts/RegistryConstants.sol";
import {IStakingMachine} from "@moc/periphery/contracts/IStakingMachine.sol";
import {IVotingMachine} from "@moc/periphery/contracts/IVotingMachine.sol";
import {IVetoMachine} from "../interfaces/IVetoMachine.sol";

contract RegistryValues is RegistryConstants {
    function _totalSupply(IRegistry registry) internal view returns (uint256) {
        return _getToken(registry).totalSupply();
    }

    function _lockStake(
        IRegistry registry,
        address mocHolder,
        uint256 untilTimestamp
    ) internal {
        _getStakingMachine(registry).lockMocs(mocHolder, untilTimestamp);
    }

    function _getLockedStake(IRegistry registry, address user) internal view returns (uint256) {
        return _getStakingMachine(registry).getLockedBalance(user);
    }

    function _getStake(IRegistry registry, address user) internal view returns (uint256) {
        return _getStakingMachine(registry).getBalance(user);
    }

    function _getToken(IRegistry registry) internal view returns (IERC20) {
        return IERC20(registry.getAddress(MOC_TOKEN));
    }

    function _getStakingMachine(IRegistry registry) internal view returns (IStakingMachine) {
        return IStakingMachine(registry.getAddress(MOC_STAKING_MACHINE));
    }

    function _getVotingMachineAddress(IRegistry registry) internal view returns (address) {
        return registry.getAddress(MOC_VOTING_MACHINE);
    }

    function _getVotingMachine(IRegistry registry) internal view returns (IVotingMachine) {
        return IVotingMachine(registry.getAddress(MOC_VOTING_MACHINE));
    }

    function _getVetoMachine(IRegistry registry) internal view returns (bool, IVetoMachine) {
        try registry.getAddress(MOC_VETO_MACHINE) returns (address result) {
            return (true, IVetoMachine(result));
        } catch Error(string memory) {
            return (false, IVetoMachine(address(0)));
        } catch (bytes memory) {
            return (false, IVetoMachine(address(0)));
        }
    }

    function _getMinStake(IRegistry registry) internal view returns (uint256) {
        return registry.getUint(MOC_VOTING_MACHINE_MIN_STAKE);
    }

    function _getPreVoteExpirationTimeDelta(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_PRE_VOTE_EXPIRATION_TIME_DELTA);
        require(ret > 0, "Invalid preVoteExpirationTimeDelta");
        return ret;
    }

    function _getMaxPreProposals(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_MAX_PRE_PROPOSALS);
        require(ret > 0, "Invalid maxPreProposals");
        return ret;
    }

    function _getPreVoteMinPCToWin(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_PRE_VOTE_MIN_PCT_TO_WIN);
        require(ret > 0, "Invalid preVoteMinPCToWin");
        return ret;
    }

    function _getVoteMinPctToVeto(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_VETO);
        require(ret > 0, "Invalid voteMinPctToVeto");
        return ret;
    }

    function _getVoteMinPctForQuorum(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_VOTE_MIN_PCT_FOR_QUORUM);
        require(ret > 0, "Invalid voteMinPctForQuorum");
        return ret;
    }

    function _getVoteMinPctToAccept(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_VOTE_MIN_PCT_TO_ACCEPT);
        require(ret > 0, "Invalid voteMinPctToAccept");
        return ret;
    }

    function _getPCTPrecision(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_PCT_PRECISION);
        require(ret >= 100, "Invalid pctPrecision");
        return ret;
    }

    function _getVotingTimeDelta(IRegistry registry) internal view returns (uint256) {
        uint256 ret = registry.getUint(MOC_VOTING_MACHINE_VOTING_TIME_DELTA);
        require(ret > 0, "Invalid votingTimeDelta");
        return ret;
    }

    function _getAcceptedStepPriorityTimeDelta(IRegistry registry)
        internal
        view
        returns (uint256)
    {
        return registry.getUint(MOC_VOTING_MACHINE_ACCEPTED_STEP_PRIORITY_TIME_DELTA);
    }
}
