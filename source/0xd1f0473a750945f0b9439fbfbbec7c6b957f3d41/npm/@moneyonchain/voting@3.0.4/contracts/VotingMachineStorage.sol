// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {Initializable} from "@openzeppelin/contracts-ethereum-package/contracts/Initializable.sol";
import {PreVotingDataLib} from "./libs/PreVotingDataLib.sol";
import {VotingDataLib} from "./libs/VotingDataLib.sol";
import {RegistryValues} from "./libs/RegistryValues.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";
import {Governed} from "@moc/periphery/contracts/moc-governance/Governance/Governed.sol";
import {ChangeContract} from "@moc/periphery/contracts/moc-governance/Governance/ChangeContract.sol";
import {IStakingMachine} from "@moc/periphery/contracts/IStakingMachine.sol";
import {IRegistry} from "@moc/periphery/contracts/IRegistry.sol";

contract VotingMachineStorage is Initializable, Governed, RegistryValues {
    using SafeMath for uint256;
    using PreVotingDataLib for PreVotingDataLib.PreVotingData;
    using VotingDataLib for VotingDataLib.VotingData;

    // Iterable list of proposals used during preVoting
    enum VotingState {
        PreVoting,
        Voting,
        Accepted
    }

    // Governor used to execute change contracts
    IGovernor public controlledGovernor;

    // Library configuration.
    IRegistry public registry;

    // Current voting round
    uint256 internal votingRound;

    struct Vote {
        address addr;
        uint96 round;
    }

    // Votes
    mapping(address => Vote) public votes;

    // The contract state
    VotingState internal votingState;
    PreVotingDataLib.PreVotingData internal preVotingData;
    VotingDataLib.VotingData internal votingData;

    enum ProposalResult {
        None,
        Accepted,
        NoQuorum,
        Vetoed
    }

    struct Proposal {
        // Accumulated votes in MOCs
        uint128 inFavorVotes;
        // Accumulated votes in MOCs
        uint128 againstVotes;
        // Accumulated vetoes in Veto tokens
        uint128 vetoes;
        // The round in which this proposal was proposed
        uint64 votingRound;
        // The result of the proposal(accepted, no quorum, vetoed)
        ProposalResult result;
        // True if the proposal was successfully executed
        bool success;
    }
    // List of all proposals that have been passed the pre-voting stage
    address[] public proposalsList;
    mapping(address => Proposal) public proposals;

    // The account that first submitted a proposal and the time at which it
    // became executable. These fields are appended before the storage gap so
    // existing proxy storage slots remain unchanged.
    mapping(address => address) public proposalProposer;
    mapping(address => uint256) public proposalAcceptedTimestamp;

    // Empty internal constructor, to prevent people from mistakenly deploying
    // an instance of this contract, which should be used via inheritance.
    // solhint-disable-next-line no-empty-blocks
    constructor() internal {}

    // Reserved storage space to allow for layout changes in the future.
    uint256[48] private ______gap;
}
