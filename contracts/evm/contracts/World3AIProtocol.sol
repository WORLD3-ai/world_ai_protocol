// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title WORLD3 AI Protocol
 * @notice A reference implementation of the WORLD3 AI Protocol (EVM version).
 *
 *         Key Points:
 *         1) One agent can only ever have one principal.
 *         2) Authorizations are per function.
 *         3) The agent->principal association is removed only when
 *            all function authorizations are revoked.
 */
contract World3AIProtocol {
    // ------------------------------------------------------------------------
    // DATA STRUCTURES
    // ------------------------------------------------------------------------

    /**
     * @dev Stores all necessary information for an agent’s authorization:
     *      - startTime: Earliest timestamp the agent can call the function.
     *      - endTime: Latest timestamp the agent can call the function.
     *      - allowedCalls: How many times the agent may call the function.
     *      - selectorIndex: Position index in the array of permitted function selectors.
     */
    struct AgentAuthorizationData {
        uint256 startTime;
        uint256 endTime;
        uint256 allowedCalls;
        uint256 selectorIndex;
    }

    /**
     * @dev Used for batch-creation or batch-update of authorizations.
     */
    struct BatchAuthorization {
        address agent;
        bytes4 functionSelector;
        uint256 startTime;
        uint256 endTime;
        uint256 allowedCalls;
        bytes signature;
    }

    // ------------------------------------------------------------------------
    // STATE VARIABLES
    // ------------------------------------------------------------------------

    // Mapping: principal -> agent -> functionSelector -> authorization data
    mapping(address => mapping(address => mapping(bytes4 => AgentAuthorizationData)))
        public principalToAgentAuthorizations;

    // Mapping: agent -> principal (reverse lookup; one agent can have exactly one principal)
    mapping(address => address) public agentToPrincipal;

    // Mapping: principal -> agent -> array of permitted function selectors
    mapping(address => mapping(address => bytes4[]))
        public principalAgentFunctionSelectors;

    // ------------------------------------------------------------------------
    // EVENTS
    // ------------------------------------------------------------------------

    event AgentAuthorized(
        address indexed principal,
        address indexed agent,
        bytes4 indexed functionSelector
    );

    event AgentRevoked(
        address indexed principal,
        address indexed agent,
        bytes4 indexed functionSelector
    );

    event AgentAuthorizationUpdated(
        address indexed principal,
        address indexed agent,
        bytes4 indexed functionSelector,
        uint256 newStartTime,
        uint256 newEndTime,
        uint256 newAllowedCalls
    );

    // ------------------------------------------------------------------------
    // MODIFIERS
    // ------------------------------------------------------------------------

    /**
     * @dev Restricts function calls to authorized agents for a specific function selector.
     *      If the caller (msg.sender) is recognized as an agent, we verify it’s authorized
     *      for the given function. If usage is depleted after this call, we remove that
     *      function selector from the agent’s list.
     */
    modifier onlyRegisteredAgent(bytes4 _functionSelector) {
        address _agent = msg.sender;
        address _principal = agentToPrincipal[_agent];

        // If _agent is recognized, verify its authorization
        if (_principal != address(0)) {
            _checkAgentAuthorization(_principal, _agent, _functionSelector);
        }

        // If _principal == address(0), then msg.sender is not recognized as an agent.
        // The call may proceed if it's the principal or some other address.
        // This is presumably by design.
        _;

        // If agent was recognized, decrement allowedCalls
        if (_principal != address(0)) {
            AgentAuthorizationData
                storage authData = principalToAgentAuthorizations[_principal][
                    _agent
                ][_functionSelector];

            // Decrement the allowed calls
            authData.allowedCalls--;
            // If no more calls are allowed, remove the function selector
            if (authData.allowedCalls == 0) {
                _removeAuthorization(_principal, _agent, _functionSelector);
            }
        }
    }

    // ------------------------------------------------------------------------
    // EXTERNAL / PUBLIC FUNCTIONS
    // ------------------------------------------------------------------------

    /**
     * @notice Authorize (or overwrite) an agent to call a specific function selector.
     *         One agent can only be tied to a single principal. If this agent is not yet
     *         associated with a principal, it sets that mapping. If it is already associated
     *         with the caller, it updates/overwrites. Otherwise, it reverts.
     *         Requires the agent's signature for permission.
     *
     * @param _agent            Address of the agent being authorized.
     * @param _functionSelector 4-byte function selector.
     * @param _startTime        Earliest time the agent can call the function.
     * @param _endTime          Latest time the agent can call the function.
     * @param _allowedCalls     How many times the agent can call the function.
     * @param _signature        Signature from the agent for permission.
     */
    function authorizeAgent(
        address _agent,
        bytes4 _functionSelector,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _allowedCalls,
        bytes memory _signature
    ) public {
        require(_agent != address(0), "Invalid agent address");
        require(_allowedCalls > 0, "Allowed calls must be > 0");

        // Optional check: ensure that endTime >= startTime if both are nonzero
        if (_startTime != 0 && _endTime != 0) {
            require(_endTime >= _startTime, "End time must be >= start time");
        }

        // Caller cannot be someone else's agent
        require(
            agentToPrincipal[msg.sender] == address(0),
            "Caller is already an agent for another principal"
        );

        // Verify agent's signature off-chain
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                msg.sender,
                _functionSelector,
                _startTime,
                _endTime,
                _allowedCalls
            )
        );
        require(
            _verifySignature(_agent, messageHash, _signature),
            "Invalid agent signature"
        );

        // Assign agent to principal if not assigned yet, otherwise must match the caller
        address currentPrincipal = agentToPrincipal[_agent];
        if (currentPrincipal == address(0)) {
            agentToPrincipal[_agent] = msg.sender; // brand-new agent
        } else {
            require(
                currentPrincipal == msg.sender,
                "Agent is assigned to a different principal"
            );
        }

        // Create/overwrite authorization
        _internalUpdateAuthorization(
            msg.sender,
            _agent,
            _functionSelector,
            _startTime,
            _endTime,
            _allowedCalls
        );
    }

    /**
     * @notice Revoke agent authorization for a specific function selector.
     *         If this is the last authorization for that agent, the agent->principal
     *         mapping is also removed.
     *
     * @param _agent            The agent to revoke.
     * @param _functionSelector The function selector being revoked.
     */
    function revokeAuthorization(
        address _agent,
        bytes4 _functionSelector
    ) external {
        require(
            agentToPrincipal[_agent] == msg.sender,
            "Unauthorized: caller is not the agent's principal"
        );

        AgentAuthorizationData
            storage authData = principalToAgentAuthorizations[msg.sender][
                _agent
            ][_functionSelector];
        require(
            authData.allowedCalls > 0,
            "No existing authorization to revoke"
        );

        _removeAuthorization(msg.sender, _agent, _functionSelector);
    }

    /**
     * @notice Check if an agent is currently authorized for a specific function selector.
     *         Reverts if the agent is not authorized.
     *
     * @param _principal        The principal that granted authorization.
     * @param _agent            The agent whose authorization is being checked.
     * @param _functionSelector The function selector to check against.
     */
    function isAgentAuthorized(
        address _principal,
        address _agent,
        bytes4 _functionSelector
    ) public view {
        _checkAgentAuthorization(_principal, _agent, _functionSelector);
    }

    /**
     * @notice Update an existing authorization without removing and re-authorizing.
     *         If the authorization does not exist, this call fails.
     *
     * @param _agent            The agent whose authorization is being updated.
     * @param _functionSelector The function selector to update.
     * @param _newStartTime     New earliest time the agent can call the function.
     * @param _newEndTime       New latest time the agent can call the function.
     * @param _newAllowedCalls  New usage allowance for the agent.
     */
    function updateAuthorization(
        address _agent,
        bytes4 _functionSelector,
        uint256 _newStartTime,
        uint256 _newEndTime,
        uint256 _newAllowedCalls
    ) external {
        require(_newAllowedCalls > 0, "Allowed calls must be > 0");

        // Optional check: ensure that endTime >= startTime if both are nonzero
        if (_newStartTime != 0 && _newEndTime != 0) {
            require(
                _newEndTime >= _newStartTime,
                "End time must be >= start time"
            );
        }

        AgentAuthorizationData
            storage authData = principalToAgentAuthorizations[msg.sender][
                _agent
            ][_functionSelector];
        require(
            authData.allowedCalls > 0,
            "No existing authorization to update"
        );

        authData.startTime = _newStartTime;
        authData.endTime = _newEndTime;
        authData.allowedCalls = _newAllowedCalls;

        emit AgentAuthorizationUpdated(
            msg.sender,
            _agent,
            _functionSelector,
            _newStartTime,
            _newEndTime,
            _newAllowedCalls
        );
    }

    /**
     * @notice Batch-create or update authorizations in a single transaction.
     * @dev If an authorization for (agent, functionSelector) does not exist, it creates it.
     *      If it already exists and belongs to msg.sender, it overwrites it.
     *
     * @param _batchData Array of BatchAuthorization items.
     */
    function batchAuthorizeAgent(
        BatchAuthorization[] calldata _batchData
    ) external {
        for (uint256 i = 0; i < _batchData.length; i++) {
            BatchAuthorization calldata item = _batchData[i];
            authorizeAgent(
                item.agent,
                item.functionSelector,
                item.startTime,
                item.endTime,
                item.allowedCalls,
                item.signature
            );
        }
    }

    // ------------------------------------------------------------------------
    // INTERNAL FUNCTIONS
    // ------------------------------------------------------------------------

    /**
     * @dev Internal function to create or overwrite an authorization.
     *      Emits AgentAuthorized on each call, which can also serve as an "update" event.
     */
    function _internalUpdateAuthorization(
        address _principal,
        address _agent,
        bytes4 _functionSelector,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _allowedCalls
    ) internal {
        AgentAuthorizationData
            storage authData = principalToAgentAuthorizations[_principal][
                _agent
            ][_functionSelector];

        // If it's a brand-new authorization for this selector, add to the agent's selector array
        if (authData.allowedCalls == 0) {
            bytes4[] storage selectorArray = principalAgentFunctionSelectors[
                _principal
            ][_agent];
            authData.selectorIndex = selectorArray.length;
            selectorArray.push(_functionSelector);
        }

        // Update/overwrite data
        authData.startTime = _startTime;
        authData.endTime = _endTime;
        authData.allowedCalls = _allowedCalls;

        emit AgentAuthorized(_principal, _agent, _functionSelector);
    }

    /**
     * @dev Internal logic to remove authorization data from mappings and arrays.
     *      Emits AgentRevoked on completion.
     */
    function _removeAuthorization(
        address _principal,
        address _agent,
        bytes4 _functionSelector
    ) internal {
        AgentAuthorizationData
            storage authData = principalToAgentAuthorizations[_principal][
                _agent
            ][_functionSelector];

        // Remove from the function selectors array by swapping with the last one
        bytes4[] storage selectorArray = principalAgentFunctionSelectors[
            _principal
        ][_agent];
        uint256 idx = authData.selectorIndex;
        uint256 lastIdx = selectorArray.length - 1;

        if (idx != lastIdx) {
            // Move the last selector into the removed position
            bytes4 lastSelector = selectorArray[lastIdx];
            selectorArray[idx] = lastSelector;
            principalToAgentAuthorizations[_principal][_agent][lastSelector]
                .selectorIndex = idx;
        }
        selectorArray.pop();

        // Clear the struct data
        delete principalToAgentAuthorizations[_principal][_agent][
            _functionSelector
        ];

        // If no more selectors remain, remove the agent->principal association
        if (selectorArray.length == 0) {
            delete agentToPrincipal[_agent];
        }

        emit AgentRevoked(_principal, _agent, _functionSelector);
    }

    /**
     * @dev Checks that an agent is authorized for a given function selector at the current time.
     *      Reverts with a clear message if it is not.
     */
    function _checkAgentAuthorization(
        address _principal,
        address _agent,
        bytes4 _functionSelector
    ) internal view {
        AgentAuthorizationData memory authData = principalToAgentAuthorizations[
            _principal
        ][_agent][_functionSelector];

        require(
            authData.allowedCalls > 0,
            "Agent not authorized: no remaining calls"
        );
        require(
            authData.startTime == 0 || block.timestamp >= authData.startTime,
            "Agent not authorized: before start time"
        );
        require(
            authData.endTime == 0 || block.timestamp <= authData.endTime,
            "Agent not authorized: after end time"
        );
    }

    /**
     * @dev Basic signature verification.
     *      For better security and user experience, consider EIP-712 typed data.
     */
    function _verifySignature(
        address _agent,
        bytes32 _messageHash,
        bytes memory _signature
    ) internal pure returns (bool) {
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
        );
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(_signature);
        return ecrecover(ethSignedMessageHash, v, r, s) == _agent;
    }

    /**
     * @dev Splits a signature into its components (r, s, v).
     */
    function _splitSignature(
        bytes memory _signature
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_signature.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
    }

    /**
     * @dev Resolve the principal address for a given agent.
     *      If the agent is not recognized, returns caller address (msg.sender).
     */
    function _resolvePrincipal(address _agent) internal view returns (address) {
        address principal = agentToPrincipal[_agent];
        return principal == address(0) ? _agent : principal;
    }
}

