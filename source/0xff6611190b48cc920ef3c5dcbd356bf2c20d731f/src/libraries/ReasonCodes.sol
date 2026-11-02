// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title ReasonCodes
 * @author 0xMithrandir
 * @notice Library for managing the list of rejection reason codes.
 */
library ReasonCodes {
    // --- Generic Reasons (0-99) ---
    uint16 public constant REASON_NONE = 0; // Default for non-rejected/disputed
    uint16 public constant REASON_TECHNICAL_ERROR = 1; // Relayer or backend internal error
    uint16 public constant REASON_MANUAL_OVERRIDE = 2; // Guardian/owner manual intervention
    uint16 public constant REASON_EXPIRED = 3; // Request expired

    // --- Rejection Reasons (100-199) - From Relayer, Watchers, or System ---
    uint16 public constant REJECT_INSUFFICIENT_COLLATERAL = 100; // User's off-chain margin/collateral is too low
    uint16 public constant REJECT_ACCOUNT_HAS_OPEN_POSITIONS = 101; // User must close positions before withdrawing
    uint16 public constant REJECT_ACCOUNT_FROZEN_OR_SANCTIONED = 102; // Compliance/risk flag
    uint16 public constant REJECT_INVALID_WITHDRAWAL_ADDRESS = 103; // Address is on a denylist
    uint16 public constant REJECT_EXCEEDS_VELOCITY_LIMIT = 104; // Withdrawal amount/frequency is too high
    uint16 public constant REJECT_REQUEST_TIMED_OUT = 105; // Request expired before processing (by Teller)
    uint16 public constant REJECT_WATCHER_QUORUM_FAILED = 106; // Watcher quorum failed to achieve consensus in time

    // --- Dispute Reasons (200-299) - From Relayer or Watcher ---
    uint16 public constant DISPUTE_SUSPICIOUS_ACTIVITY = 200; // Potential fraud, account takeover, or other anomaly
    uint16 public constant DISPUTE_STATE_MISMATCH = 201; // Discrepancy between on-chain and off-chain state

    // --- Cancellation Reasons (300-399) ---
    uint16 public constant CANCELLED_BY_USER = 300; // Withdrawal explicitly cancelled by the user
}
