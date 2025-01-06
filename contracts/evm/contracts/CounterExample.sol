// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./World3AIProtocol.sol";

/**
 * @title CounterExample
 * @notice Demonstrates how principals can delegate increment permission to agents,
 *         while only principals can reset the counter to zero.
 */
contract CounterExample is World3AIProtocol {
    // Mapping: principal -> current counter value
    mapping(address => uint256) private userCounters;

    event CounterIncremented(address indexed principal, uint256 newValue);
    event CounterReset(address indexed principal);

    /**
     * @dev Increment the principal's counter by 1.
     *      Protected by `onlyRegisteredAgent(bytes4(keccak256("incrementMyCounter()")))`.
     *
     *      If msg.sender is an agent, we check if it’s authorized
     *      to call "incrementMyCounter()".
     *      If msg.sender is the principal, they’re allowed by default
     *      because the modifier only restricts recognized agents.
     */
    function incrementMyCounter()
        external
        onlyRegisteredAgent(bytes4(keccak256("incrementMyCounter()")))
    {
        address actualOwner = _resolvePrincipal(msg.sender);

        userCounters[actualOwner]++;
        emit CounterIncremented(actualOwner, userCounters[actualOwner]);
    }

    /**
     * @dev Reset the principal’s counter to zero. Only the principal can do this.
     */
    function resetMyCounter() external {
        // If msg.sender is an agent, `_resolvePrincipal(msg.sender)` returns the principal's address (non-zero).
        // Only the actual principal (where `_resolvePrincipal(msg.sender) == address(0)`) can reset.
        require(
            _resolvePrincipal(msg.sender) == msg.sender,
            "Only principal can reset counter"
        );

        userCounters[msg.sender] = 0;
        emit CounterReset(msg.sender);
    }

    /**
     * @notice Returns the counter value for the given user.
     */
    function getCounter(address user) external view returns (uint256) {
        return userCounters[user];
    }
}
