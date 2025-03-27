# World3 AI Protocol - Sui Implementation

## Table of Contents

1. [World3AIProtocol](#1-world3aiprotocol)
   - [Module Details](#module-details)
   - [Key Functionalities](#key-functionalities)
   - [Sui-Oriented Design](#sui-oriented-design)
2. [CounterExample](#2-counterexample)
   - [Module Details](#module-details-1)
   - [Functionality](#functionality)
3. [Usage Guide](#usage-guide)
   - [Deployment](#1-deployment)
   - [Authorizing an Agent](#2-authorizing-an-agent)
   - [Agent Execution](#3-agent-execution)
   - [Revoking or Updating Authorizations](#4-revoking-or-updating-authorizations)
   - [Principal-Only Operations](#5-principal-only-operations)
4. [Security Considerations](#security-considerations)
5. [Sui vs. EVM - Key Design Differences](#suivsevm-key-design-differences)

## 1. **World3AIProtocol**

The **World3AIProtocol** module provides the core structs, tables, and logic for on-chain delegation in Sui.

### Module Details

```move
module world3_ai_protocol::world3_ai_protocol {
    // Core registry for tracking agent-principal relationships
    struct Registry has key, store {
        id: UID,
        // Agent -> Principal mapping
        agent_to_principal: Table<address, address>,
        // Principal -> Agent -> Authorization ID mapping
        principal_agent_authorizations: Table<address, Table<address, ID>>,
        // Principal -> List of agents (for efficient iteration)
        principal_agents: Table<address, vector<address>>
    }

    // Authorization object storing all function authorizations for a principal-agent pair
    struct AgentAuthorization has key {
        id: UID,
        // The principal who authorized the agent
        principal: address,
        // The agent who is authorized
        agent: address,
        // Map of function selectors to authorization data
        authorized_functions: Table<FunctionSelector, FunctionAuthorization>,
        // Track function selectors for easier iteration
        function_selectors: vector<FunctionSelector>
    }

    // Authorization data for a single function
    struct FunctionAuthorization has store, drop {
        // Timestamp when the authorization becomes valid (0 = no restriction)
        start_time: u64,
        // Timestamp when the authorization expires (0 = no restriction)
        end_time: u64,
        // Number of times the agent can call this function
        allowed_calls: u64
    }

    // Key functions include:
    // - create_module_registry(...)
    // - create_agent_with_authorization(...)
    // - batch_authorize_agent(...)
    // - revoke_authorization_for_function(...)
    // - revoke_all_authorizations(...)
    // - update_authorization(...)
    // - validate_access(...)
    // - is_authorized_for_function(...)
    // - decrease_allowed_calls(...)
}
```

### Key Functionalities

1. **Registry Management**
   - `create_module_registry(...)`: Creates a new registry for a module to track agent-principal relationships
   - `resolve_principal(...)`: Returns the principal for an address (self if not an agent)

2. **Agent Authorization**
   - `create_agent_with_authorization(...)`: Creates a new agent with initial function authorization
   - `authorize_agent(...)`: Authorizes an agent for a specific function
   - `batch_authorize_agent(...)`: Authorizes an agent for multiple functions in a batch
   - `update_authorization(...)`: Updates time constraints and allowed calls for an existing authorization

3. **Access Control**
   - `validate_access(...)`: Validates if a caller has access to a protected function
   - `is_authorized_for_function(...)`: Checks if an agent is authorized for a specific function
   - `decrease_allowed_calls(...)`: Decrements the allowed calls counter after successful execution

4. **Revocation**
   - `revoke_authorization_for_function(...)`: Revokes authorization for a specific function
   - `revoke_all_authorizations(...)`: Removes all authorizations for an agent

### Sui-Oriented Design

The World3 AI Protocol implementation on Sui leverages several unique features of the Sui blockchain to enable efficient and secure delegation:

1. **Object-Centric Architecture**
   - `Registry` and `AgentAuthorization` are modeled as Sui objects with distinct UIDs
   - The protocol leverages Sui's ownership model to create clear boundaries between owned and shared resources

2. **Shared Object Model**
   - The `Registry` is published as a shared object, making it globally accessible while maintaining concurrency safety
   - Each `AgentAuthorization` is a shared object allowing both principals and agents to interact with it concurrently

3. **Table-Based Storage**
   - Instead of mappings, the protocol uses Sui's `Table` type for dynamic storage of authorizations
   - Tables provide key-value storage with O(1) lookups and direct access to stored values
   - The `principal_agents` table maintains vector lists for efficient agent enumeration

4. **Granular Concurrency**
   - The design allows multiple authorization operations to occur in parallel for unrelated principal-agent pairs
   - Leverages Sui's parallel transaction execution to improve throughput

5. **Move's Strong Type System**
   - Utilizes Move's ability constraints (`key`, `store`, `copy`, `drop`) to enforce security properties
   - Function selectors are represented as strongly typed structures rather than byte arrays
   - Events are typed structs providing rich, structured information for indexers

6. **Per-Module Registry Isolation**
   - Each module creates its own registry instance to prevent cross-module authorization interference
   - The module initializer automatically creates and shares the registry object

These design choices maximize the benefits of Sui's unique execution model while maintaining the security guarantees needed for delegation.

---

## 2. **CounterExample**

This module demonstrates how a Sui application can leverage the **World3AIProtocol** to implement delegated access control.

### Module Details

```move
module world3_ai_protocol::counter_example {
    // Module state that owns the protocol registry
    struct CounterModuleState has key {
        id: UID,
        // The Registry object for authorization
        registry: Registry
    }

    // Per-user counter data
    struct UserCounter has key {
        id: UID,
        // The owner's address
        owner: address,
        // The counter value
        value: u64
    }

    // Key functions include:
    // - create_counter(...)
    // - increment_my_counter(...)
    // - agent_increment_counter(...)
    // - reset_my_counter(...)
    // - get_counter_value(...)
    // - get_counter_owner(...)
}
```

### Functionality

- **create_counter()**
  - Creates a new counter owned by the caller
  - Counter starts with a value of 0

- **increment_my_counter()**
  - Increments the counter by 1
  - Can only be called by the counter owner

- **agent_increment_counter()**
  - Allows an authorized agent to increment someone else's counter
  - Protected by protocol validation checks
  - Decreases the agent's allowed calls after successful execution

- **reset_my_counter()**
  - Resets the counter to 0
  - Can only be called by the counter owner

---

## Usage Guide

### 1. Deployment

Deploy the **World3AIProtocol** and **CounterExample** modules using the Sui CLI:

```bash
sui client publish --gas-budget 30000000
```

After deployment, the module initialization will create a shared `CounterModuleState` object that contains the registry.

### 2. Authorizing an Agent

```move
// Example: principal granting an agent 5 calls for "incrementMyCounter()" with no time restrictions
let registry = // get reference to module_state.registry
let auth_id = Protocol::create_agent_with_authorization(
    registry,
    agent_address,
    string::utf8(b"incrementMyCounter()"),
    0,  // start_time (0 = no restriction)
    0,  // end_time (0 = no restriction)
    5,  // allowed_calls
    ctx
);
```

### 3. Agent Execution

```move
// The agent can now call this function up to 5 times
counter_example::agent_increment_counter(&mut module_state, &mut counter, &mut auth, ctx);
```

### 4. Revoking or Updating Authorizations

```move
// Remove authorization for incrementMyCounter()
Protocol::revoke_authorization_for_function(
    &mut auth,
    string::utf8(b"incrementMyCounter()"),
    ctx
);

// Or update the authorization
Protocol::update_authorization(
    &mut auth,
    string::utf8(b"incrementMyCounter()"),
    0,  // new_start_time
    0,  // new_end_time
    10, // new_allowed_calls
    ctx
);

// Completely revoke all authorizations for an agent
Protocol::revoke_all_authorizations(&mut registry, &mut auth, ctx);
```

### 5. Principal-Only Operations

Some operations like `reset_my_counter()` are restricted to the principal only:

```move
// Only the counter owner can reset their counter
counter_example::reset_my_counter(&module_state, &mut counter, ctx);
```

---

## Security Considerations

1. **Limited Delegation**
   - Principal-only functions like `reset_my_counter()` cannot be delegated
   - All authorizations are time-bound and usage-limited

2. **Multi-level Authorization**
   - Time constraints: `start_time` and `end_time` to limit when an agent can act
   - Usage constraints: `allowed_calls` to limit how many times an agent can act

3. **Fine-grained Control**
   - Each function can have its own authorization parameters
   - Function selectors ensure precise scoping of agent permissions

4. **Authorization Registration**
   - An agent can only be registered to one principal at a time
   - Prevents conflicts of interest and responsibility confusion

5. **Registry Ownership**
   - Each module creates and manages its own registry
   - Prevents cross-module authorization interference

## Sui vs. EVM - Key Design Differences

While the World3 AI Protocol shares conceptual similarities across Sui and EVM environments, there are notable distinctions in design and execution:

1. Object-Centric Model vs. Account-Centric Model  
   - On Sui, every resource is an on-chain object with its own unique ID. This allows fine-grained permissions, explicit object ownership, and single-writer concurrency without global nonce usage.  
   - On EVM, smart contracts and externally owned accounts share the same address space, and state transitions rely on nonce-based transaction ordering.

2. Move Language vs. Solidity  
   - Sui leverages Move, a language centered around safe asset management, strong type system, and data-race-free concurrency.  
   - EVM uses Solidity (or other high-level languages) compiled to EVM bytecode, relying on a shared global state model and synchronous calls between contracts.

3. Transaction Context and Concurrency  
   - The Sui `TxContext` provides access to per-transaction data (like timestamps, transaction sender) in a single handle, enabling parallel transaction execution in many cases.  
   - On EVM, transactions execute sequentially with a global state. Concurrency is simulated via re-entrancy guards or layering solutions off-chain.

4. Unique Sharing Semantics  
   - Sui objects can be "shared" to allow multiple owners, or remain "owned" by a single address. The protocol leverages "shared objects" for the registry and authorization objects.  
   - EVM contracts typically store shared data in a single global state, guarded by modifiers and access controls.

5. Event Emission and Indexing  
   - Sui events are typed Move structs, which can be read off-chain by indexers or decoders.  
   - On EVM, events are part of the contract ABI, emitted as logs accessible via logs bloom and block explorers.

These differences shape how the World3 AI Protocol handles object ownership, concurrency, and transaction flows on Sui versus EVM.
