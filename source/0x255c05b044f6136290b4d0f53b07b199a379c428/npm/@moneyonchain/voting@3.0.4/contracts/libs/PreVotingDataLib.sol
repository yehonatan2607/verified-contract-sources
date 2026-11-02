// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {ProposalInfoLib} from "./ProposalInfoLib.sol";

/*
    Abstract contract meant to be reused.
*/
library PreVotingDataLib {
    using SafeMath for uint256;
    using ProposalInfoLib for ProposalInfoLib.ProposalInfoData;

    struct PreVotingData {
        // Proposal Information
        ProposalInfoLib.ProposalInfoData proposalInfo;
    }

    /**
    PreVotingList data initializations
    */
    function _init(PreVotingData storage self) internal {
        self.proposalInfo = ProposalInfoLib._init();
    }

    /**
    The proposal was never voted or is new in this round

    @param _proposalAddr Address of the change contract that will be executed if this vote is successful
    */
    function _isEmptyProposal(
        PreVotingData storage self,
        uint256 _votingRound,
        address _proposalAddr
    ) internal view returns (bool) {
        if (!self.proposalInfo._contains(_proposalAddr)) {
            return true;
        }
        ProposalInfoLib.ProposalData memory proposal = self.proposalInfo._get(_proposalAddr);
        return __isReusableProposal(_votingRound, proposal);
    }

    /**
    Insert or update a proposal. If the list is full then replace the one with less stake.

    @param _proposalAddr address of the change contract
    @param _stake stake used
    */
    function _upsert(
        PreVotingData storage self,
        uint256 _votingRound,
        uint256 _maxPreProposals,
        uint256 _preVoteExpirationTimeDelta,
        address _proposalAddr,
        uint256 _stake
    ) internal returns (bool) {
        // Reuse a proposal.
        if (self.proposalInfo._contains(_proposalAddr)) {
            ProposalInfoLib.ProposalData memory proposal = self.proposalInfo._get(_proposalAddr);
            if (!__isReusableProposal(_votingRound, proposal)) {
                // Can't reuse an active proposal
                return false;
            }

            self.proposalInfo._set(
                _proposalAddr,
                __newProposal(_votingRound, _preVoteExpirationTimeDelta, _stake)
            );
            return true;
        }

        // Completely new proposal, there is a place in the list
        if (self.proposalInfo._length() < _maxPreProposals) {
            self.proposalInfo._push(
                _proposalAddr,
                __newProposal(_votingRound, _preVoteExpirationTimeDelta, _stake)
            );
            return true;
        }

        // Completely new proposal but there is no place in the list, must check if there are proposals to remove.
        (uint256 minIdx, uint256 minVal) = __findAPlace(self, _votingRound);
        if (_stake > minVal) {
            self.proposalInfo._replace(
                minIdx,
                _proposalAddr,
                __newProposal(_votingRound, _preVoteExpirationTimeDelta, _stake)
            );
            return true;
        }
        return false;
    }

    /**
     Add votes to a proposal

     @param _proposalAddr address of the change contract
     @param _stake stake used
     */
    function _addVotes(
        PreVotingData storage self,
        uint256 _votingRound,
        address _proposalAddr,
        uint256 _stake
    ) internal returns (bool) {
        if (!self.proposalInfo._contains(_proposalAddr)) {
            return false;
        }
        ProposalInfoLib.ProposalData memory proposal = self.proposalInfo._get(_proposalAddr);
        if (__isReusableProposal(_votingRound, proposal)) {
            return false;
        }
        // We don't let them vote an expired proposal
        if (__isExpired(proposal)) {
            return false;
        }
        proposal.votes = _stake.add(proposal.votes);
        self.proposalInfo._set(_proposalAddr, proposal);
        return true;
    }

    /**
      Remove from the pre-voting list an expired proposal

      @param _proposalAddr address of the change contract
    */
    function _remove(
        PreVotingData storage self,
        uint256 _votingRound,
        address _proposalAddr
    ) internal returns (bool) {
        if (!self.proposalInfo._contains(_proposalAddr)) {
            return false;
        }
        ProposalInfoLib.ProposalData memory proposal = self.proposalInfo._get(_proposalAddr);
        if (!__isReusableProposal(_votingRound, proposal)) {
            return false;
        }
        self.proposalInfo._remove(_proposalAddr);
        return true;
    }

    /**
    Get a winner proposal.
    Search the proposal with max pre-votes if it is expired then that proposal is the winner.
    If two proposals has the same quantity of votes take the with older expiration time.
    @param _preVoteMinPCToWin minimum percentage of vote needed to participate (moc votes/total moc in circulation).
    @param _pctPrecision percentage precision.
    @param _totalMOCSupply total supply of moc to calculate percentages.
    */
    function _getWinnerProposal(
        PreVotingData storage self,
        uint256 _votingRound,
        uint256 _preVoteMinPCToWin,
        uint256 _pctPrecision,
        uint256 _totalMOCSupply
    ) internal view returns (address candidateAddress, uint256 maxVal) {
        address currentAddress;
        ProposalInfoLib.ProposalData memory candidateProposal;
        ProposalInfoLib.ProposalData memory currentProposal;
        uint256 maxVotes = 0;

        // Search the proposal (expired or not) with the max quantity of votes.
        for (uint256 i = 0; i < self.proposalInfo._length(); i++) {
            (currentAddress, currentProposal) = self.proposalInfo._get(i);

            if (__isReusableProposal(_votingRound, currentProposal)) {
                continue;
            }

            // Not enough votes to participate.
            if (
                currentProposal.votes.mul(_pctPrecision) < _totalMOCSupply.mul(_preVoteMinPCToWin)
            ) {
                continue;
            }

            if (
                currentProposal.votes > maxVotes ||
                (currentProposal.votes == maxVotes &&
                    currentProposal.expirationTimestamp < candidateProposal.expirationTimestamp)
            ) {
                maxVotes = currentProposal.votes;
                candidateAddress = currentAddress;
                candidateProposal = currentProposal;
            }
        }

        // if the candidate is expired we have a winner.
        if (__isExpired(candidateProposal)) {
            return (candidateAddress, candidateProposal.votes);
        }
        return (address(0), 0);
    }

    /**
    Get the proposal count
    */
    function _getProposalCount(PreVotingData storage self) internal view returns (uint256) {
        return self.proposalInfo._length();
    }

    /**
    Get proposal address and information by index

    @param _index Index of proposal to query. 
    */
    function _getProposalByIndex(PreVotingData storage self, uint256 _index)
        internal
        view
        returns (
            address proposalAddress,
            uint256 votingRound,
            uint256 votes,
            uint256 expirationTimeStamp
        )
    {
        (address addr, ProposalInfoLib.ProposalData memory data) = self.proposalInfo._get(_index);
        return (addr, data.votingRound, data.votes, data.expirationTimestamp);
    }

    /**
    Check if a is valid.

    @param _votes stake used
    */
    function __newProposal(
        uint256 _votingRound,
        uint256 _preVoteExpirationTimeDelta,
        uint256 _votes
    ) internal view returns (ProposalInfoLib.ProposalData memory) {
        return
            ProposalInfoLib.ProposalData({
                votingRound: _votingRound,
                votes: _votes, // solhint-disable-next-line not-rely-on-time
                expirationTimestamp: block.timestamp + _preVoteExpirationTimeDelta
            });
    }

    /**
    Find a place in the list, at this point I'm sure that there is no winner proposal and that the list is
    full (length > 1). We use the first  expired or reusable slot. If all the proposals are active then we
    search for the one that has minimum votes.
    */
    function __findAPlace(PreVotingData storage self, uint256 _votingRound)
        internal
        view
        returns (uint256 minIdx, uint256 minVal)
    {
        ProposalInfoLib.ProposalData memory proposal;
        (, proposal) = self.proposalInfo._get(0);
        if (__isReusableProposal(_votingRound, proposal) || __isExpired(proposal)) {
            return (0, 0);
        }

        // The proposal in idx == 0 is not expired => is active.
        (minIdx, minVal) = (0, proposal.votes);
        for (uint256 i = 1; i < self.proposalInfo._length(); i++) {
            (, proposal) = self.proposalInfo._get(i);
            if (__isReusableProposal(_votingRound, proposal) || __isExpired(proposal)) {
                return (i, 0);
            }
            // Not expired proposals, calculate the min and max
            if (proposal.votes < minVal) {
                (minIdx, minVal) = (i, proposal.votes);
            }
        }

        // We only use an active proposal if there are no expired proposals or free slots.
        return (minIdx, minVal);
    }

    function _isExpired(
        PreVotingData storage self,
        uint256 _votingRound,
        address _proposalAddr
    ) internal view returns (bool) {
        if (!self.proposalInfo._contains(_proposalAddr)) {
            return false;
        }
        ProposalInfoLib.ProposalData memory proposal = self.proposalInfo._get(_proposalAddr);
        if (__isReusableProposal(_votingRound, proposal)) {
            return false;
        }
        return __isExpired(proposal);
    }

    /**
    The proposal was never voted or is new in this round

    @param _proposal proposal data
    */
    function __isReusableProposal(
        uint256 _votingRound,
        ProposalInfoLib.ProposalData memory _proposal
    ) internal pure returns (bool) {
        return (_proposal.votingRound != _votingRound);
    }

    function __isExpired(ProposalInfoLib.ProposalData memory _proposal)
        internal
        view
        returns (bool)
    {
        // solhint-disable-next-line not-rely-on-time
        return (_proposal.expirationTimestamp < block.timestamp);
    }
}
