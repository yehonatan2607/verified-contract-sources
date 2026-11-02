// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.8.0;


import "./UniswapV3Oracle.sol";
import "./interfaces/IPriceProvider.sol";


contract UniswapV3OracleUSD is UniswapV3Oracle {

    address public _wrappedToken;
    IPriceProvider public _btcPriceProvider;

    /// @param pool The Uniswap v3 pool to get the price of the token
    /// @param twapInterval The time interval in seconds to get the twap over
    /// @param wrappedToken The Wrapped BTC token address
    /// @param btcPriceProvider The BTC/USD Price Provider address
    constructor(
        IUniswapV3Pool pool,
        uint32 twapInterval,
        address wrappedToken,
        IPriceProvider btcPriceProvider
    ) UniswapV3Oracle(pool, twapInterval, wrappedToken) {
        _wrappedToken = wrappedToken;
        _btcPriceProvider = btcPriceProvider;
    }

    /// legacy peek function
    function peek() override public view returns (bytes32 price, bool isValid) {
        (bytes32 btcPrice, bool btcPriceIsValid) = _btcPriceProvider.peek();
        uint256 priceFromPool = getPriceFromPool(_uniswapV3Pool, _twapInterval, _wrappedToken);
        price = bytes32(FullMath.mulDiv(uint256(btcPrice), priceFromPool, 10**18));
        isValid = btcPriceIsValid;
    }

    // Return the current price.
    function getPrice() override public view returns(uint256) {
        (bytes32 peek_price,) = peek();
        return uint256(peek_price); 
    }
    
    // Return if the price is not expired.
    function getIsValid() public view returns(bool) {
        (, bool isValid) = peek();
        return isValid; 
    }

}
