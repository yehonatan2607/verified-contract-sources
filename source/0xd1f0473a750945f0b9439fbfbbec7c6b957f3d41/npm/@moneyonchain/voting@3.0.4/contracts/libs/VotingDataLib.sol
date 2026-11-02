// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import {ProposalInfoLib} from "./ProposalInfoLib.sol";

/*
    Abstract contract meant to be reused.
*/
library VotingDataLib {
    using SafeMath for uint256;
    using ProposalInfoLib for ProposalInfoLib.ProposalInfoData;
    uint256 internal constant PRECISION = 10 ** 18;

    struct VotingData {
        // Pre-voting winner proposal
        address winnerProposal;
        // Accumulated votes in MOCs
        uint256 inFavorVotes;
        // Accumulated votes in MOCs
        uint256 againstVotes;
        // voting process expiration time.
        uint256 votingExpirationTime;
    }

    /**
    Voting data initializations
    */
    function _init(VotingData storage self) internal {
        self.winnerProposal = address(0);
        self.inFavorVotes = 0;
        self.againstVotes = 0;
    }

    /**
     */
    function _startVoting(
        VotingData storage self,
        uint256 _votingTimeDelta,
        address _winnerProposal,
        uint256 _inFavorVotes,
        uint256 _againstVotes
    ) internal {
        self.winnerProposal = _winnerProposal;
        self.inFavorVotes = _inFavorVotes;
        self.againstVotes = _againstVotes;
        // solhint-disable-next-line not-rely-on-time
        self.votingExpirationTime = _votingTimeDelta + block.timestamp;
    }

    /**
     */
    function _addVotes(VotingData storage self, uint256 _stake, bool _inFavorAgainst) internal {
        if (_inFavorAgainst) {
            self.inFavorVotes = self.inFavorVotes.add(_stake);
        } else {
            self.againstVotes = self.againstVotes.add(_stake);
        }
    }

    /**
     */
    function _isVeto(
        VotingData storage self,
        uint256 _PCTPrecision,
        uint256 _voteMinPctToVeto,
        uint256 _totalMOC,
        uint256 _vetoPCT
    ) internal view returns (bool) {
        if (
            self.againstVotes.mul(_PCTPrecision) > _totalMOC.mul(_voteMinPctToVeto) ||
            _vetoPCT.mul(_PCTPrecision) > _voteMinPctToVeto.mul(PRECISION)
        ) return true;
    }

    /**
     */
    function _isAccepted(
        VotingData storage self,
        uint256 _PCTPrecision,
        uint256 /*_voteMinPctToVeto*/,
        uint256 _voteMinPctForQuorum,
        uint256 _voteMinPctToAccept,
        uint256 _totalMOC,
        uint256 _totalVotes
    ) internal view returns (bool) {
        uint256 inFavor = self.inFavorVotes.mul(_PCTPrecision);
        // Still don't expired.
        if (!_isExpired(self)) {
            return false;
        }
        // Less than 20% of total mocs in circulation
        if (inFavor < _totalMOC.mul(_voteMinPctForQuorum)) {
            return false;
        }
        // After expiration in favor < 50% * (in favor + against)
        if (inFavor < _voteMinPctToAccept.mul(_totalVotes)) {
            return false;
        }
        return true;
    }

    function _isAccepted(
        VotingData storage self,
        uint256 _PCTPrecision,
        uint256 _voteMinPctToVeto,
        uint256 _voteMinPctForQuorum,
        uint256 _voteMinPctToAccept,
        uint256 _totalMOC
    ) internal view returns (bool) {
        return
            _isAccepted(
                self,
                _PCTPrecision,
                _voteMinPctToVeto,
                _voteMinPctForQuorum,
                _voteMinPctToAccept,
                _totalMOC,
                self.againstVotes.add(self.inFavorVotes)
            );
    }

    /**
     */
    function _isExpired(VotingData storage self) internal view returns (bool) {
        // solhint-disable-next-line not-rely-on-time
        return (self.votingExpirationTime < block.timestamp);
    }
}
