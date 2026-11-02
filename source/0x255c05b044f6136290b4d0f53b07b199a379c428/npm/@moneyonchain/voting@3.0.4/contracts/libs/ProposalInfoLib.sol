// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.6.12;

import {SafeMath} from "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";

/*
    Abstract contract meant to be reused.
    An iterable unique map of address -> proposals.
*/
library ProposalInfoLib {
    using SafeMath for uint256;

    struct ProposalData {
        // The round in which this proposal was proposed
        uint256 votingRound;
        // Accumulated votes in MOCs
        uint256 votes;
        // Expiration time
        uint256 expirationTimestamp;
    }

    struct ProposalInfoData {
        address[] proposalList;
        mapping(address => ProposalData) proposals;
    }

    /**
      ProposalInfoData data initializations
    */
    function _init() internal pure returns (ProposalInfoData memory) {
        address[] memory emptyList;
        return ProposalInfoData(emptyList);
    }

    /**
    Add to the set, increasing its size

    @param _key the key of the mapping
    @param _data the value to assign
    */
    function _push(
        ProposalInfoData storage self,
        address _key,
        ProposalData memory _data
    ) internal {
        require(!_contains(self, _key), "Duplicated key");
        require(_data.votingRound != 0, "Invalid votingRound value");
        self.proposals[_key] = _data;
        self.proposalList.push(_key);
    }

    /**
    Replace an element by index. After an iteration the resulting index can be use to replace an element

    @param _idx the index in the list for the old element
    @param _newKey the new key of the mapping
    @param _data the new value to assign
    */
    function _replace(
        ProposalInfoData storage self,
        uint256 _idx,
        address _newKey,
        ProposalData memory _data
    ) internal {
        require(_idx < _length(self), "Index out of range_replace");
        require(_data.votingRound != 0, "Invalid votingRound value");
        delete self.proposals[self.proposalList[_idx]];
        require(!_contains(self, _newKey), "Duplicated key");
        self.proposalList[_idx] = _newKey;
        self.proposals[_newKey] = _data;
    }

    /**
    Replace an element by index address

    @param _oldKey the kef of the old element
    @param _newKey the new key of the mapping
    @param _data the new value to assign
    */
    function _replace(
        ProposalInfoData storage self,
        address _oldKey,
        address _newKey,
        ProposalData memory _data
    ) internal {
        _replace(self, _find(self, _oldKey), _newKey, _data);
    }

    /**
    Gets an element by index (used during iteration).

    @param _idx the index used to get the element
    */
    function _get(ProposalInfoData storage self, uint256 _idx)
        internal
        view
        returns (address, ProposalData memory)
    {
        require(_idx < _length(self), "Index out of range_get");
        return (self.proposalList[_idx], self.proposals[self.proposalList[_idx]]);
    }

    /**
    Gets an element by address.

    @param _key the key used to get the element
    */
    function _get(ProposalInfoData storage self, address _key)
        internal
        view
        returns (ProposalData memory)
    {
        require(_contains(self, _key), "Key not found");
        return self.proposals[_key];
    }

    /**
    Set a value by address.

    @param _key the key used to set the element value
    @param _data the new value to set
    */
    function _set(
        ProposalInfoData storage self,
        address _key,
        ProposalData memory _data
    ) internal {
        require(_contains(self, _key), "Invalid key");
        require(_data.votingRound != 0, "Invalid votingRound value");
        self.proposals[_key] = _data;
    }

    /**
    Set a value by index.

    @param _idx the index of element to change
    @param _data the new value to set
    */
    function _set(
        ProposalInfoData storage self,
        uint256 _idx,
        ProposalData memory _data
    ) internal {
        require(_idx < _length(self), "Index out of range_set");
        _set(self, self.proposalList[_idx], _data);
    }

    /**
    Get the quantity of elements

    */
    function _length(ProposalInfoData storage self) internal view returns (uint256) {
        return self.proposalList.length;
    }

    /**
    Check if the map contains a specific address.

    @param _key the address to check
    */
    function _contains(ProposalInfoData storage self, address _key) internal view returns (bool) {
        return _key != address(0) && self.proposals[_key].votingRound != 0;
    }

    /**
    Remove from the list by index (reducing its size)

    @param _idx the index of the element to remove
    */
    function _remove(ProposalInfoData storage self, uint256 _idx) internal {
        require(_idx < _length(self), "Index out of range _remove");
        delete self.proposals[self.proposalList[_idx]];
        self.proposalList[_idx] = self.proposalList[self.proposalList.length - 1];
        self.proposalList.pop();
    }

    /**
      Remove from the list by address (reducing its size).
      This method does a linear search of the element, use with care

      @param _key the key used to search the element to remove
    */
    function _remove(ProposalInfoData storage self, address _key) internal {
        _remove(self, _find(self, _key));
    }

    /**
      This method does a linear search of some key, use with care

      @param _key the key to that is searched
    */
    function _find(ProposalInfoData storage self, address _key) internal view returns (uint256) {
        require(_contains(self, _key), "Key not found");
        for (uint256 i = 0; i < _length(self); i++) {
            if (self.proposalList[i] == _key) {
                return i;
            }
        }
        require(false, "Missing key?");
        return 0;
    }
}
