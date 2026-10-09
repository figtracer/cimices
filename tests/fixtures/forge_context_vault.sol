// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC4626 {
    /// @notice Returns the maximum assets that can be deposited into this ERC-4626 vault.
    /// @dev maxDeposit accounts for all deposit limits and returns zero when deposits are disabled.
    /// @param receiver The account that receives shares.
    /// @return assets The maximum executable deposit amount.
    function maxDeposit(address receiver) external view returns (uint256 assets);

    /// @notice Simulates redeeming shares from this ERC-4626 vault.
    /// @dev previewRedeem returns the redeem bound in the same transaction.
    /// @param shares The shares to redeem.
    /// @return assets The assets that the redemption returns.
    function previewRedeem(uint256 shares) external view returns (uint256 assets);
}
