// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title AggregatorV3Interface
 * @notice Minimal Chainlink AggregatorV3 interface for price feeds
 */
interface AggregatorV3Interface {
    /**
     * @notice Returns the number of decimals used by the aggregator
     * @return The number of decimals
     */
    function decimals() external view returns (uint8);

    /**
     * @notice Returns the latest round data
     * @return roundId The round ID
     * @return answer The answer
     * @return startedAt The timestamp of the round start
     * @return updatedAt The timestamp of the round update
     * @return answeredInRound The round ID of the answer
     */
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
