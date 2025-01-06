# Contracts

## Table of Contents

1. [World3AIProtocol](#1-world3aiprotocol)
   - [Contract Details](#contract-details)
   - [Key Functionalities](#key-functionalities)
2. [CounterExample](#2-counterexample)
   - [Contract Details](#contract-details-1)
   - [Functionality](#functionality)
3. [Usage Guide](#usage-guide)
   - [Deployment](#1-deployment)
   - [Authorizing an Agent](#2-authorizing-an-agent)
   - [Agent Execution](#3-agent-execution)
   - [Revoking or Updating Authorizations](#4-revoking-or-updating-authorizations)
   - [Principal-Only Reset](#5-principal-only-reset)
4. [Security Considerations](#security-considerations)

## 1. **World3AIProtocol**

The **World3AIProtocol** contract provides the core mappings, structs, and logic for on-chain delegation.

### Contract Details

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract World3AIProtocol {
    // Mapping: principal -> agent -> functionSelector -> authorization data
    mapping(address => mapping(address => mapping(bytes4 => AgentAuthorizationData))) public principalToAgentAuthorizations;

    // Mapping: agent -> principal
    mapping(address => address) public agentToPrincipal;

    // Mapping: principal -> agent -> array of function selectors
    mapping(address => mapping(address, bytes4[])) public principalAgentFunctionSelectors;

    struct AgentAuthorizationData {
        uint256 startTime;
        uint256 endTime;
        uint256 allowedCalls;
        uint256 selectorIndex;
    }

    // Key functions include:
    // - authorizeAgent(...)
    // - revokeAuthorization(...)
    // - updateAuthorization(...)
    // - batchAuthorizeAgent(...)
    // - Modifiers and internal checks (e.g., onlyRegisteredAgent(...))
    // - _verifySignature(...) for agent consent
    // - _removeAuthorization(...) for cleanup
}
```

### Key Functionalities

1. **authorizeAgent(...)**
   - Sets or overwrites an agent’s authorization for a given function.
   - Requires the agent’s signature to confirm consent.

2. **onlyRegisteredAgent(...)** (modifier)
   - Restricts function calls to valid agents or the principal itself.
   - Automatically decrements `allowedCalls`.

3. **Revoke & Update**
   - `revokeAuthorization(...)`: Removes a single function’s authorization.
   - `updateAuthorization(...)`: Modifies usage/time bounds without removing the agent entirely.

4. **Internal Checks**
   - `_verifySignature(...)`: Validates agent consent via signature.
   - `_removeAuthorization(...)`: Handles cleanup when authorization is exhausted or revoked.

---

## 2. **CounterExample**

This contract demonstrates how a dApp might inherit from **World3AIProtocol** and enforce partial delegation.

### Contract Details

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./World3AIProtocol.sol";

contract CounterExample is World3AIProtocol {
    mapping(address => uint256) private userCounters;

    // Example snippet: agent-restricted increment
    function incrementMyCounter()
        external
        onlyRegisteredAgent(bytes4(keccak256("incrementMyCounter()")))
    {
        address actualOwner = _resolvePrincipal(msg.sender);
        userCounters[actualOwner]++;
        // ...
    }

    // Example snippet: principal-only reset
    function resetMyCounter() external {
        require(
            _resolvePrincipal(msg.sender) == msg.sender,
            "Only principal can reset"
        );
        userCounters[msg.sender] = 0;
        // ...
    }
    
    // Utility
    function getCounter(address user) external view returns (uint256) {
        return userCounters[user];
    }
}
```

### Functionality

- **incrementMyCounter()**
  - Protected by `onlyRegisteredAgent(bytes4(keccak256("incrementMyCounter()")))`.
  - Agents must be authorized for `incrementMyCounter()`.
  - Principals can call freely (the modifier only restricts recognized agents).

- **resetMyCounter()**
  - Only the principal can perform a reset.
  - If `msg.sender` is an agent, `_resolvePrincipal(msg.sender)` returns a different address, failing the `require`.

---

## Usage Guide

### 1. Deployment

Deploy the **CounterExample** contract, which inherits **World3AIProtocol**.

### 2. Authorizing an Agent

```solidity
// Example: principal granting an agent 10 calls for "incrementMyCounter()" until a given endTime
counterExample.authorizeAgent(
    agentAddress,
    bytes4(keccak256("incrementMyCounter()")),
    block.timestamp,              // _startTime
    block.timestamp + 3600,       // _endTime (1 hour)
    10,                           // _allowedCalls
    agentSignature
);
```

### 3. Agent Execution

```solidity
// If agent is authorized, usage is decremented by 1 each time.
counterExample.incrementMyCounter();
```

### 4. Revoking or Updating Authorizations

```solidity
// Remove specific authorization for incrementMyCounter
counterExample.revokeAuthorization(
    agentAddress,
    bytes4(keccak256("incrementMyCounter()"))
);
```

### 5. Principal-Only Reset

Only the principal can execute `resetMyCounter()`. If an agent tries, the call will fail.

---

## Security Considerations

1. **Limited Delegation**
   - The modifier `onlyRegisteredAgent(...)` never blocks the principal, preventing lockout.
   - Agents are strictly checked by usage/time windows.

2. **Agent Consent**
   - `authorizeAgent(...)` includes a signature check (`_verifySignature`), ensuring agent opt-in.

3. **Auto-Revoke on Zero Usage**
   - The protocol removes authorization when `allowedCalls` drops to zero.

4. **Immediate Revocation**
   - Principals can instantly remove an agent’s authorization via `revokeAuthorization(...)`.

5. **Time-Bound**
   - Agents can be restricted to specific time frames (`_startTime`, `_endTime`).

