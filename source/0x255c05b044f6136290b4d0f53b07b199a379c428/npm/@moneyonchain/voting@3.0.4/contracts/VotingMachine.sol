// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {IERC20} from "@openzeppelin/contracts-ethereum-package/contracts/token/ERC20/IERC20.sol";
import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {VotingMachineStorage} from "./VotingMachineStorage.sol";
import {IGovernor} from "@moc/periphery/contracts/moc-governance/Governance/IGovernor.sol";
import {Governed} from "@moc/periphery/contracts/moc-governance/Governance/Governed.sol";
import {IRegistry} from "@moc/periphery/contracts/IRegistry.sol";
import {IVotingMachine} from "@moc/periphery/contracts/IVotingMachine.sol";
import {IStakingMachine} from "@moc/periphery/contracts/IStakingMachine.sol";
import {ChangeContract} from "@moc/periphery/contracts/moc-governance/Governance/ChangeContract.sol";
import {IVetoMachine} from "./interfaces/IVetoMachine.sol";

contract VotingMachine is VotingMachineStorage, IVotingMachine {
    using SafeMath for uint256;

    event PreVoteEvent(
        address indexed user,
        address indexed proposal,
        uint256 stake,
        uint256 round
    );
    event VoteEvent(
        address indexed user,
        address indexed proposal,
        bool inFavorAgainst,
        uint256 stake,
        uint256 round
    );
    event PreVoteStepEvent(address indexed proposal, uint256 votesInFavor, uint256 round);
    event VoteStepEvent(address indexed proposal, uint256 round, ProposalResult result);
    event AcceptedStepEvent(address indexed proposal, uint256 round, bool success);
    event UnregisterEvent(address indexed proposal, uint256 round);

    modifier atState(VotingState _state) {
        require(votingState == _state, "Invalid state");
        _;
    }

    constructor() public initializer {
        // Avoid leaving the implementation contract uninitialized.
    }

    /**
     @notice Contract creation

     @param _governor The address of the contract which governs this one
     @param _controlledGovernor The address of the governor that executes the change contracts
    */
    function initialize(
        IGovernor _governor,
        IGovernor _controlledGovernor,
        IRegistry _registry
    ) external initializer {
        Governed._initialize(_governor);
        votingState = VotingState.PreVoting;
        registry = _registry;

        votingRound = 1;
        controlledGovernor = _controlledGovernor;
        preVotingData._init();
        votingData._init();
    }

    /**
    get current contract state

    */
    function getState() external view override returns (uint256) {
        return uint256(votingState);
    }

    /**
        return the current voting round
        */
    function getVotingRound() external view override returns (uint256) {
        return votingRound;
    }

    /**
    Pre Vote

    @param _changeContractAddress Address of the change contract that will be executed if this vote is successful
    */
    function preVote(
        address _changeContractAddress
    ) external override atState(VotingState.PreVoting) {
        IRegistry localRegistry = registry;
        uint256 localVotingRound = votingRound;
        require(_changeContractAddress != address(0), "address must be != 0");
        (address winnerProposal, ) = _getWinnerProposal();
        require(winnerProposal == address(0), "There is a winner proposal");

        require(
            !preVotingData._isExpired(localVotingRound, _changeContractAddress),
            "Proposal expired"
        );

        uint256 stake = _getStake(localRegistry, msg.sender);
        Vote memory _vote = votes[msg.sender];
        if (_alreadyVoted(_vote) && !preVotingData._isExpired(localVotingRound, _vote.addr)) {
            // This is necessary to avoid storing the voting history.
            require(_vote.addr == _changeContractAddress, "Must vote the same proposal");
            uint256 locked = _getLockedStake(localRegistry, msg.sender);
            require(stake > locked, "Not enough stake");
            stake = stake - locked;
        }
        // solhint-disable-next-line not-rely-on-time
        _lockStake(
            localRegistry,
            msg.sender,
            (block.timestamp).add(_getVotingTimeDelta(localRegistry))
        );
        votes[msg.sender] = Vote(_changeContractAddress, _toUint96(localVotingRound));

        if (preVotingData._isEmptyProposal(localVotingRound, _changeContractAddress)) {
            require(stake > _getMinStake(localRegistry), "Not enough stake");
            require(
                preVotingData._upsert(
                    localVotingRound,
                    _getMaxPreProposals(localRegistry),
                    _getPreVoteExpirationTimeDelta(localRegistry),
                    _changeContractAddress,
                    stake
                ),
                "Not enough to add a proposal"
            );
            proposalProposer[_changeContractAddress] = msg.sender;
        } else {
            require(
                preVotingData._addVotes(votingRound, _changeContractAddress, stake),
                "Proposal expired"
            );
        }
        emit PreVoteEvent(msg.sender, _changeContractAddress, stake, localVotingRound);
    }

    /**
    Vote a proposal

    @param _inFavorAgainst Type of vote
    */
    function vote(bool _inFavorAgainst) external override atState(VotingState.Voting) {
        IRegistry localRegistry = registry;
        uint256 stake = _getStake(localRegistry, msg.sender);
        Vote memory _vote = votes[msg.sender];

        // Those that voted something different than the winner proposal can use they whole stake
        if (_alreadyVoted(_vote) && _vote.addr == votingData.winnerProposal) {
            uint256 locked = _getLockedStake(localRegistry, msg.sender);
            require(stake > locked, "Not enough stake");
            stake = stake - locked;
        }
        _lockStake(
            localRegistry,
            msg.sender,
            (block.timestamp).add(_getVotingTimeDelta(localRegistry))
        );
        votes[msg.sender] = Vote(votingData.winnerProposal, _toUint96(votingRound));
        votingData._addVotes(stake, _inFavorAgainst);
        emit VoteEvent(msg.sender, votingData.winnerProposal, _inFavorAgainst, stake, votingRound);
    }

    function _toUint96(uint256 value) internal pure returns (uint96) {
        require(value < 2 ** 96, "SafeCast: value doesn't fit in 96 bits");
        return uint96(value);
    }

    /**
        Return vote info.
    */
    function getVoteInfo()
        external
        view
        returns (address winnerProposal, uint256 inFavorVotes, uint256 againstVotes)
    {
        if (votingState != VotingState.Voting) {
            return (address(0), 0, 0);
        }
        return (votingData.winnerProposal, votingData.inFavorVotes, votingData.againstVotes);
    }

    /**
    Vote Condition
    */
    function vetoCondition() external override {}

    /**
    Veto
    */
    function veto() external override {}

    function readyToPreVoteStep() external view override returns (bool) {
        (address winnerProposal, ) = _getWinnerProposal();
        return (winnerProposal != address(0));
    }

    /**
    preVoteStep
    */
    function preVoteStep() external override atState(VotingState.PreVoting) {
        (address winnerProposal, uint256 votesInFavor) = _getWinnerProposal();
        require(winnerProposal != address(0), "No winner proposal");

        proposalsList.push(winnerProposal);
        votingState = VotingState.Voting;
        // Expires all the pre-voting proposals.
        votingData._startVoting(_getVotingTimeDelta(registry), winnerProposal, votesInFavor, 0);
        emit PreVoteStepEvent(winnerProposal, votesInFavor, votingRound);
    }

    function readyToVoteStep() external view override returns (bool) {
        return (isVeto() || _isAccepted() || votingData._isExpired());
    }

    /**
    voteStep
    */
    function voteStep() external override atState(VotingState.Voting) {
        bool changedState = false;
        (bool isVeto, uint256 vetoes) = _isVeto();
        Proposal memory prop = Proposal({
            inFavorVotes: uint128(votingData.inFavorVotes),
            againstVotes: uint128(votingData.againstVotes),
            vetoes: uint128(vetoes),
            votingRound: uint64(votingRound),
            result: ProposalResult.None,
            success: false
        });
        if (isVeto) {
            prop.result = ProposalResult.Vetoed;
            votingState = VotingState.PreVoting;
            votingRound = votingRound + 1;
            changedState = true;
        } else if (_isAccepted()) {
            prop.result = ProposalResult.Accepted;
            votingState = VotingState.Accepted;
            votingRound = votingRound + 1;
            proposalAcceptedTimestamp[votingData.winnerProposal] = block.timestamp;
            changedState = true;
        } else if (votingData._isExpired()) {
            prop.result = ProposalResult.NoQuorum;
            votingState = VotingState.PreVoting;
            votingRound = votingRound + 1;
            changedState = true;
        }
        // if there was a state change, emit the event and store the proposal result.
        if (changedState) {
            emit VoteStepEvent(
                votingData.winnerProposal,
                votingRound - 1, // votingRound was already incremented
                prop.result
            );
            proposals[votingData.winnerProposal] = prop;
        }
    }

    /**
    vetoStep
    */
    function vetoStep() external override {}

    /**
    acceptedStep
    */
    function acceptedStep() external override atState(VotingState.Accepted) {
        address proposalAddress = votingData.winnerProposal;
        address proposer = proposalProposer[proposalAddress];
        uint256 acceptedTimestamp = proposalAcceptedTimestamp[proposalAddress];
        uint256 acceptedStepPriorityTimeDelta = _getAcceptedStepPriorityTimeDelta(registry);
        if (
            acceptedTimestamp != 0 &&
            acceptedStepPriorityTimeDelta != 0 &&
            proposer != address(0) &&
            block.timestamp < acceptedTimestamp.add(acceptedStepPriorityTimeDelta)
        ) {
            require(
                msg.sender == proposer,
                "Only proposer can execute during priority window"
            );
        }
        // These values only apply to the current accepted execution.
        delete proposalProposer[proposalAddress];
        delete proposalAcceptedTimestamp[proposalAddress];
        // Effects before interaction: close the Accepted state before external call.
        votingState = VotingState.PreVoting;
        try controlledGovernor.executeChange(ChangeContract(proposalAddress)) {
            proposals[proposalAddress].success = true;
        } catch (bytes memory) {
            proposals[proposalAddress].success = false;
        }
        emit AcceptedStepEvent(
            proposalAddress,
            votingRound - 1, // votingRound was already incremented in voteStep
            proposals[proposalAddress].success
        );
    }

    /**
    will the call to unregister be successfull?

    @param _changeContractAddress Address of the change contract that will be executed if this vote is successful
    */
    function canUnregister(address _changeContractAddress) external view override returns (bool) {
        return (_changeContractAddress != address(0) &&
            preVotingData._isEmptyProposal(votingRound, _changeContractAddress));
    }

    /**
    Unregister a proposal, free the assets it uses.

    @param _changeContractAddress Address of the change contract that will be executed if this vote is successful
    */
    function unregister(address _changeContractAddress) external override {
        require(_changeContractAddress != address(0), "address must be != 0");
        require(preVotingData._remove(votingRound, _changeContractAddress), "Can't remove");
        emit UnregisterEvent(_changeContractAddress, votingRound);
    }

    /**
    get the maximum total expiration time of a voting process.

    function __totalExpirationTime() internal view returns (uint256) {
        return _getPreVoteExpirationTimeDelta(registry) + _getVotingTimeDelta(registry);
    }*/

    /**
    The used still didn't vote in this round
    */
    function _alreadyVoted(Vote memory _vote) internal view returns (bool) {
        return (_vote.round == votingRound);
    }

    function _isAccepted() internal view returns (bool) {
        IRegistry localRegistry = registry;
        return
            votingData._isAccepted(
                _getPCTPrecision(localRegistry),
                _getVoteMinPctToVeto(localRegistry),
                _getVoteMinPctForQuorum(localRegistry),
                _getVoteMinPctToAccept(localRegistry),
                totalSupply(),
                getTotalAgainstVotes().add(votingData.inFavorVotes)
            );
    }

    function _isVeto() internal view returns (bool, uint256) {
        uint256 vetoes = _getVetoMachineVotes();
        bool isVeto = votingData._isVeto(
            _getPCTPrecision(registry),
            _getVoteMinPctToVeto(registry),
            totalSupply(),
            vetoes
        );
        return (isVeto, vetoes);
    }

    function isVeto() public view returns (bool) {
        (bool isVeto_, ) = _isVeto();
        return isVeto_;
    }

    function getVetoMachineVotes() public view returns (uint256) {
        return _getVetoMachineVotes();
    }

    function _getWinnerProposal() internal view returns (address candidate, uint256 maxVal) {
        return
            preVotingData._getWinnerProposal(
                votingRound,
                _getPreVoteMinPCToWin(registry),
                _getPCTPrecision(registry),
                totalSupply()
            );
    }

    function _getVetoMachineVotes() internal view returns (uint256 total) {
        if (uint256(votingState) != uint256(VotingState.Voting)) {
            return 0;
        }
        (bool gotVeto, IVetoMachine vetoMac) = _getVetoMachine(registry);
        uint256 againstVotes = 0;
        if (gotVeto) {
            try vetoMac.getVetoPct(votingData.winnerProposal, votingRound) returns (
                uint256 result
            ) {
                againstVotes = result;
            } catch Error(string memory) {
                againstVotes = 0;
            } catch (bytes memory) {
                againstVotes = 0;
            }
        }
        return againstVotes;
    }

    // This would be the total amount of mocs, added the veto machines votes, if corresponds.
    function totalSupply() public view returns (uint256 total) {
        return _totalSupply(registry);
    }

    function getTotalAgainstVotes() public view returns (uint256 total) {
        return votingData.againstVotes;
    }

    /**
    Get the pre-voting registered proposal count.
    */
    function getProposalCount() external view override returns (uint256) {
        return preVotingData._getProposalCount();
    }

    /**
    Get pre-voting proposal address and information by index

    @param _index Index of proposal to query.
    */
    function getProposalByIndex(
        uint256 _index
    )
        external
        view
        override
        returns (
            address proposalAddress,
            uint256 votingRound,
            uint256 votes,
            uint256 expirationTimeStamp
        )
    {
        return preVotingData._getProposalByIndex(_index);
    }

    /**
    Get voting data
    */
    function getVotingData()
        external
        view
        override
        returns (
            address winnerProposal,
            uint256 inFavorVotes,
            uint256 againstVotes,
            uint256 votingExpirationTime
        )
    {
        return (
            votingData.winnerProposal,
            votingData.inFavorVotes,
            votingData.againstVotes,
            votingData.votingExpirationTime
        );
    }

    /**
        Get user vote
    */
    function getUserVote(
        address user
    ) external view override returns (address voteAddress, uint256 voteRound) {
        Vote memory _vote = votes[user];
        return (_vote.addr, _vote.round);
    }

    /**
        Get proposals length
    */
    function getProposalsLength() external view returns (uint256) {
        return proposalsList.length;
    }
}
