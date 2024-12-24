# WORLD3’s WORLD AI Protocol – Core Design
A flexible on-chain delegation framework that allows **principals** to securely and granularly authorize **agents** (e.g., AI agent or service accounts) to perform specific actions on their behalf.

---

## **Overview**

Many decentralized applications (**dApps**) require that users (the **principals**) delegate specific tasks—such as in-game actions, yield-farming steps, or other repeated functions—to external **agents**. The **WORLD3’s WORLD AI Protocol** manages this delegation securely by:

- Restricting **agent** permissions to specific function signatures  
- Defining **time-bound** and usage-limited delegations  
- Allowing **principals** to revoke delegated permissions at any time  

By incorporating **granular authorization**, the protocol aims to keep user assets and game states secure while enabling AI-driven or automated account interactions.

---

## **Key Features**

1. **Function-Level Permissions**  
   Grant or revoke access per function signature, giving the **principal** full control over what an **agent** can do.

2. **Time-Bound Access**  
   Authorizations can have start and end timestamps for limited-duration operations.

3. **Usage Allowance**  
   A credit-like system to limit how many times an **agent** can invoke an authorized function.

4. **Automatic De-Authorization**  
   When an **agent**’s usage allowance runs out or the time window expires, the protocol automatically revokes authorization.

5. **Easy Revocation**  
   **Principals** can revoke an **agent**’s authorization at any time—no questions asked.

6. **Event Logging**  
   Emitted events facilitate real-time tracking of who got authorized or revoked and for which functions.

7. **Extensible & Chain-Agnostic**  
   The design can be adapted to multiple blockchains such as Ethereum, SUI, Solana, NEAR, etc.

---

## **High-Level Workflow**

1. **Principal Authorizes Agent**  
   - The **principal** calls an authorization function, providing:  
     - The **agent**’s address  
     - The function hash (e.g., `keccak256("myFunction(uint,uint)")`)  
     - **Time bounds** (start/end)  
     - **Usage allowance** (e.g., 10 calls)

2. **Data Recorded**  
   - The protocol records these details in mappings keyed by `principal → agent → functionSignature`.

3. **Agent Calls a Protected Function**  
   - A modifier checks whether the caller (**agent**) is still validly authorized (e.g., usage allowance > 0, time within range).

4. **Usage Decrement & Potential Auto-Revoke**  
   - Each successful call consumes one usage allowance.  
   - If usage allowance hits zero, authorization automatically ends.

5. **Revocation**  
   - The **principal** can manually revoke an **agent** at any point, removing that **agent**’s ability to call the function.

---

## **Protocol Architecture**

The generic architecture can be summarized as follows:

- **Core Mappings**  
  - `principalAgentAuthorizations[principal][agent][functionHash]`: Tracks usage limits, time bounds, etc.  
  - `registeredPrincipalOfAgent[agent]`: Tracks which **principal** (if any) the **agent** is currently acting for.  
  - `permittedFunctionSignatures[principal][agent]`: An array of function hashes authorized for a specific **agent**.

- **Data Struct: AgentAuthorizationData**  
  - **authorizationStart**: Block timestamp from which the **agent** can invoke a function  
  - **authorizationEnd**: Block timestamp after which the **agent** can no longer invoke the function  
  - **usageAllowance**: How many times the **agent** can successfully call the function  
  - **hashArrayIndex**: An index to help manage function hashes in the `permittedFunctionSignatures` array

- **Modifiers / Check Functions**  
  - `onlyRegisteredAgent(functionSignature)` checks if `msg.sender` is an authorized **agent**, if **time constraints** are valid, and if **usageAllowance** is still > 0.

- **Events**  
  - `AgentAuthorized(principal, agent, functionHash)`  
  - `AgentRevoked(principal, agent, functionHash)`

---

## **Compare to Account Abstraction (AA)**

### **Similarity to AA**  
The **WORLD3’s WORLD AI Protocol** is conceptually similar to **Account Abstraction (AA)** in that it abstracts away the need for the user’s private key for each on-chain action. Instead, you delegate certain operational permissions to a proxy account (the **agent**).

### **Delegated Permissions vs. Private Keys**  
In a classic **AA** flow, the user’s contract-based account might need to sign off on every transaction. In **WORLD3’s WORLD AI Protocol**, a **principal** can simply authorize an **agent** for specific tasks without providing ongoing signatures or private key access.

### **Parallel or Combined Use**  
The **agent** itself can also be an **AA**-based account. This means both the **principal** and the **agent** can take advantage of **AA** features (like multisig, paymaster-based gas costs, etc.).

### **Ideal for AI Automation**  
In traditional **AA** setups, you might still need the user’s involvement for each transaction unless it’s orchestrated by the contract. With **WORLD3’s WORLD AI Protocol**, you cleanly separate critical operations from mundane tasks, letting **AI** handle trivial functions while the **user** retains full control over wallet assets.

### **Bridging into Existing Projects**  
By combining **AA** with the **WORLD3 Protocol**, we can potentially bridge any user-facing action in existing deployed contracts. The user’s **AA** contract could manage the overarching signing logic, while the **WORLD3 Protocol** delegates certain function calls to an **agent** for tasks like gaming, yield farming, or off-hours automation.

---

## **Future Roadmap**

1. **Role-Based Permissions**  
   - Ability to assign multiple function signatures to a “role” (e.g., “WorkerRole”) and authorize the **agent** once for that role.

2. **Account Abstraction (AA)**  
   - Integrate with **AA** to streamline user experience and handle more sophisticated use cases.  
   - Users could manage advanced logic for signatures and verify them on-chain without externally held keys.

3. **Gasless Meta-Transactions**  
   - Provide a meta-transaction flow so **AI agents** do not need to hold ETH/MATIC/etc. for gas.  
   - Potentially integrate with solutions like **OpenGSN** or chain-native gas relay providers.

4. **Cross-Chain Compatibility**  
   - Deploy protocol logic on multiple **EVM** networks, **SUI**, **NEAR**, or other chains, while preserving the same **function-level delegation** concepts.

---

## **Conclusion**

**WORLD3’s WORLD AI Protocol** provides a solid foundation for secure, controlled, and **time-bound delegation** of on-chain operations. By leveraging improved naming conventions, thorough event logging, and an extensible architecture, the protocol caters to a wide variety of use cases—including on-chain games, **DeFi** yield strategies, and **AI-powered** automation.

Moving forward, we aim to incorporate **role-based permissions**, **account abstraction**, **gasless meta-transactions**, and **multi-call expansions**. These enhancements will make it even simpler for **dApp** developers and end-users to safely delegate tasks, all while retaining strict control over their on-chain assets and data.


