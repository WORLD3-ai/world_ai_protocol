module world3_ai_protocol::world3_ai_protocol {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use std::string::{Self, String};
    use std::vector;
    
    // Move test_scenario import to be test_only
    #[test_only]
    use sui::test_scenario::{Self as ts, Scenario};
    
    /// Error codes
    /// @dev Invalid agent address (e.g., zero address)
    const EInvalidAgent: u64 = 0;
    /// @dev Invalid number of allowed calls (must be > 0)
    const EInvalidCalls: u64 = 1;
    /// @dev Invalid time range (end time must be >= start time)
    const EInvalidTimeRange: u64 = 2;
    /// @dev Caller is registered as an agent for someone else
    const ECallerIsAgent: u64 = 3;
    /// @dev Agent is already registered with a different principal
    const EAgentHasDifferentPrincipal: u64 = 4;
    /// @dev Only the principal can perform this action
    const EOnlyPrincipal: u64 = 10;
    /// @dev Caller is neither the owner nor an authorized agent
    const ENotOwnerOrAgent: u64 = 11;
    /// @dev Function not authorized for the agent
    const EFunctionNotAuthorized: u64 = 13;
    
    /// Function selector type (equivalent to bytes4 in Solidity)
    /// @dev Represents a function identifier for authorization purposes
    struct FunctionSelector has store, copy, drop {
        value: String
    }
    
    /// Authorization data for a single function
    /// @dev Contains time bounds and call limits for a specific function authorization
    struct FunctionAuthorization has store, drop {
        /// Timestamp when the authorization becomes valid (0 = no restriction)
        start_time: u64,
        /// Timestamp when the authorization expires (0 = no restriction)
        end_time: u64,
        /// Number of times the agent can call this function (decreases with each call)
        allowed_calls: u64
    }
    
    /// Agent authorization - A SINGLE SHARED OBJECT per principal-agent pair
    /// Contains all function authorizations for this principal-agent relationship
    /// @dev Central object that tracks all authorizations between a principal and their agent
    struct AgentAuthorization has key {
        id: UID,
        /// The principal who authorized the agent
        principal: address,
        /// The agent who is authorized
        agent: address,
        /// Map of function selectors to authorization data
        authorized_functions: Table<FunctionSelector, FunctionAuthorization>,
        /// Track function selectors for easier iteration
        function_selectors: vector<FunctionSelector>
    }
    
    /// Central Registry that tracks agent-principal relationships
    /// @dev Global registry for the protocol that maintains mappings between agents and principals
    struct Registry has key, store {
        id: UID,
        /// Agent -> Principal mapping
        agent_to_principal: Table<address, address>,
        /// Principal -> Agent -> Authorization ID mapping
        principal_agent_authorizations: Table<address, Table<address, ID>>,
        /// Principal -> List of agents (for efficient iteration)
        principal_agents: Table<address, vector<address>>
    }
    
    /// Batch authorization data for multiple function selectors in one transaction
    /// @dev Helper structure for batch authorization operations
    struct BatchAuthorizationData has drop {
        /// Function selector to authorize
        function_selector: String,
        /// Timestamp when the authorization becomes valid (0 = no restriction)
        start_time: u64,
        /// Timestamp when the authorization expires (0 = no restriction)
        end_time: u64,
        /// Number of times the agent can call this function
        allowed_calls: u64
    }
    
    /// Events
    /// @dev Emitted when an agent is authorized for a function
    struct AgentAuthorized has copy, drop {
        principal: address,
        agent: address,
        function_selector: String,
        authorization_id: ID
    }
    
    /// @dev Emitted when an agent's authorization is revoked
    struct AgentRevoked has copy, drop {
        principal: address,
        agent: address,
        function_selector: String,
        authorization_id: ID
    }
    
    /// @dev Emitted when an agent's authorization is updated
    struct AgentAuthorizationUpdated has copy, drop {
        principal: address,
        agent: address,
        function_selector: String,
        new_start_time: u64,
        new_end_time: u64,
        new_allowed_calls: u64,
        authorization_id: ID
    }
    
    /// @dev Emitted when a module-specific Registry is created
    struct ModuleRegistryCreated has copy, drop {
        registry_id: ID
    }
    
    /// Query data structure to return information about a function authorization
    /// @dev Used to return authorization details to callers
    struct FunctionAuthorizationInfo has copy, drop {
        /// Function selector string
        function_selector: String,
        /// Timestamp when the authorization becomes valid (0 = no restriction)
        start_time: u64,
        /// Timestamp when the authorization expires (0 = no restriction)
        end_time: u64,
        /// Number of times the agent can call this function (decreases with each call)
        allowed_calls: u64
    }
    
    /// Creates the initial setup for the World3 AI Protocol
    /// @dev Module initializer - currently does nothing as each module creates its own registry
    fun init(_ctx: &mut TxContext) {
        // Each module creates its own registry as needed
        // No shared objects needed for initialization
    }
    
    /// Create a new Registry for a module
    /// @dev Creates a registry object that will be owned by the calling module
    /// @return Registry - The created registry object
    public fun create_module_registry(ctx: &mut TxContext): Registry {
        // Create module-specific registry
        let registry = Registry {
            id: object::new(ctx),
            agent_to_principal: table::new(ctx),
            principal_agent_authorizations: table::new(ctx),
            principal_agents: table::new(ctx)
        };
        
        let registry_id = object::id(&registry);
        
        // Emit module registry creation event
        event::emit(ModuleRegistryCreated { 
            registry_id
        });
        
        // Return the registry (module will own it directly)
        registry
    }
    
    /// Get or create the agent authorization object for a principal-agent pair
    /// @dev Retrieves an existing authorization or creates a new one if needed
    /// Also registers the agent in the appropriate registry tables
    /// @param registry - The central registry
    /// @param principal - The principal address
    /// @param agent - The agent address
    /// @param ctx - The transaction context
    /// @return (ID, bool) - (authorization_id, is_new) Tuple containing the ID and whether it was newly created
    #[allow(unused_function)]
    fun get_or_create_authorization(
        registry: &mut Registry,
        principal: address,
        agent: address,
        ctx: &mut TxContext
    ): (ID, bool) {
        // Check if we already have an authorization for this principal-agent pair
        if (table::contains(&registry.principal_agent_authorizations, principal)) {
            let principal_agents = table::borrow(&registry.principal_agent_authorizations, principal);
            
            if (table::contains(principal_agents, agent)) {
                return (*table::borrow(principal_agents, agent), false)
            }
        };
        
        // Create a new authorization object
        let auth = AgentAuthorization {
            id: object::new(ctx),
            principal,
            agent,
            authorized_functions: table::new(ctx),
            function_selectors: vector::empty<FunctionSelector>()
        };
        
        let auth_id = object::id(&auth);
        
        // Register in principal -> agent mapping
        if (!table::contains(&registry.principal_agent_authorizations, principal)) {
            table::add(&mut registry.principal_agent_authorizations, principal, table::new<address, ID>(ctx));
        };
        
        let principal_agents = table::borrow_mut(&mut registry.principal_agent_authorizations, principal);
        table::add(principal_agents, agent, auth_id);
        
        // Register in agent -> principal mapping
        table::add(&mut registry.agent_to_principal, agent, principal);
        
        // Track agent in the principal's agent list for efficient iteration
        if (!table::contains(&registry.principal_agents, principal)) {
            table::add(&mut registry.principal_agents, principal, vector::empty<address>());
        };
        let agents_list = table::borrow_mut(&mut registry.principal_agents, principal);
        vector::push_back(agents_list, agent);
        
        // Share the authorization object
        transfer::share_object(auth);
        
        (auth_id, true)
    }
    
    /// Internal helper to validate authorization parameters
    /// @dev Validates authorization parameters for consistency and requirements
    /// @param caller - The caller's address
    /// @param principal - The principal's address  
    /// @param agent - The agent's address
    /// @param start_time - Authorization start time
    /// @param end_time - Authorization end time
    /// @param allowed_calls - Number of allowed calls
    fun validate_authorization_params(
        caller: address,
        principal: address,
        agent: address,
        start_time: u64,
        end_time: u64,
        allowed_calls: u64
    ) {
        // Verify the caller is the principal
        assert!(caller == principal, EOnlyPrincipal);
        
        assert!(agent != @0x0, EInvalidAgent);
        assert!(allowed_calls > 0, EInvalidCalls);
        
        // Optional check: ensure that end_time >= start_time if both are nonzero
        if (start_time != 0 && end_time != 0) {
            assert!(end_time >= start_time, EInvalidTimeRange);
        };
    }
    
    /// Internal helper to create or update a function authorization
    /// @dev Creates or updates a function authorization in the authorization object
    /// @param auth - The authorization object to update
    /// @param function_selector - The function selector string
    /// @param start_time - Authorization start time
    /// @param end_time - Authorization end time
    /// @param allowed_calls - Number of allowed calls
    /// @return bool - Whether this was a new authorization (true) or an update (false)
    fun create_or_update_function_authorization(
        auth: &mut AgentAuthorization,
        function_selector: String,
        start_time: u64,
        end_time: u64,
        allowed_calls: u64
    ): bool {
        let function_selector_obj = FunctionSelector { value: function_selector };
        let is_new = !table::contains(&auth.authorized_functions, function_selector_obj);
        
        if (is_new) {
            // Add new authorization and track the selector
            let func_auth = FunctionAuthorization {
                start_time,
                end_time,
                allowed_calls
            };
            table::add(&mut auth.authorized_functions, function_selector_obj, func_auth);
            vector::push_back(&mut auth.function_selectors, function_selector_obj);
        } else {
            // Update existing authorization
            let existing_auth = table::borrow_mut(&mut auth.authorized_functions, function_selector_obj);
            existing_auth.start_time = start_time;
            existing_auth.end_time = end_time;
            existing_auth.allowed_calls = allowed_calls;
        };
        
        is_new
    }
    
    /// Authorize an agent for a function
    /// @param registry - The module's registry
    /// @param auth - The agent authorization object to update
    /// @param function_selector - The function selector string
    /// @param start_time - When the authorization becomes valid (0 = immediately)
    /// @param end_time - When the authorization expires (0 = never)
    /// @param allowed_calls - How many times the agent can call this function
    public fun authorize_agent(
        _registry: &mut Registry,
        auth: &mut AgentAuthorization,
        function_selector: String,
        start_time: u64,
        end_time: u64,
        allowed_calls: u64,
        ctx: &TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        
        // Validate parameters - principal is the caller
        validate_authorization_params(caller, principal, auth.agent, start_time, end_time, allowed_calls);
        
        // Create or update the authorization
        let _is_new = create_or_update_function_authorization(
            auth, 
            function_selector, 
            start_time, 
            end_time, 
            allowed_calls
        );
        
        // Emit event
        event::emit(AgentAuthorized {
            principal,
            agent: auth.agent,
            function_selector,
            authorization_id: object::id(auth)
        });
    }
    
    /// Create a new agent with initial function authorization
    /// @param registry - The central registry
    /// @param agent - The agent address to authorize
    /// @param function_selector - The function selector string
    /// @param start_time - When the authorization becomes valid (0 = immediately)
    /// @param end_time - When the authorization expires (0 = never)
    /// @param allowed_calls - How many times the agent can call this function
    /// @return ID - The ID of the created authorization object
    public fun create_agent_with_authorization(
        registry: &mut Registry,
        agent: address,
        function_selector: String,
        start_time: u64,
        end_time: u64,
        allowed_calls: u64,
        ctx: &mut TxContext
    ): ID {
        let caller = tx_context::sender(ctx);
        let principal = caller;
        
        // Validate parameters
        validate_authorization_params(caller, principal, agent, start_time, end_time, allowed_calls);
        
        // Caller cannot be someone else's agent
        if (table::contains(&registry.agent_to_principal, principal)) {
            assert!(table::borrow(&registry.agent_to_principal, principal) == &principal, ECallerIsAgent);
        };
        
        // Assign agent to principal if not assigned yet, otherwise must match the caller
        if (table::contains(&registry.agent_to_principal, agent)) {
            assert!(table::borrow(&registry.agent_to_principal, agent) == &principal, EAgentHasDifferentPrincipal);
        };
        
        // Create a new authorization object
        let function_selector_obj = FunctionSelector { value: function_selector };
        let function_selectors = vector::empty<FunctionSelector>();
        vector::push_back(&mut function_selectors, function_selector_obj);
        
        let auth_functions = table::new<FunctionSelector, FunctionAuthorization>(ctx);
        table::add(&mut auth_functions, function_selector_obj, FunctionAuthorization {
            start_time,
            end_time,
            allowed_calls
        });
        
        let auth = AgentAuthorization {
            id: object::new(ctx),
            principal,
            agent,
            authorized_functions: auth_functions,
            function_selectors
        };
        
        let auth_id = object::id(&auth);
        
        // Register in principal -> agent mapping
        if (!table::contains(&registry.principal_agent_authorizations, principal)) {
            table::add(&mut registry.principal_agent_authorizations, principal, table::new<address, ID>(ctx));
        };
        
        let principal_agents = table::borrow_mut(&mut registry.principal_agent_authorizations, principal);
        table::add(principal_agents, agent, auth_id);
        
        // Register in agent -> principal mapping
        table::add(&mut registry.agent_to_principal, agent, principal);
        
        // Track agent in the principal's agent list for efficient iteration
        if (!table::contains(&registry.principal_agents, principal)) {
            table::add(&mut registry.principal_agents, principal, vector::empty<address>());
        };
        let agents_list = table::borrow_mut(&mut registry.principal_agents, principal);
        vector::push_back(agents_list, agent);
        
        // Share the authorization object
        transfer::share_object(auth);
        
        // Emit event
        event::emit(AgentAuthorized {
            principal,
            agent,
            function_selector,
            authorization_id: auth_id
        });
        
        auth_id
    }
    
    /// Authorize an agent for multiple functions in a single transaction
    /// @dev Batch authorize an agent for multiple functions in a single transaction
    /// @param registry - The central registry
    /// @param auth - The agent authorization object to update
    /// @param authorizations - Vector of batch authorization data
    public fun batch_authorize_agent(
        _registry: &mut Registry,
        auth: &mut AgentAuthorization,
        authorizations: vector<BatchAuthorizationData>,
        ctx: &TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        let agent = auth.agent;
        let auth_id = object::id(auth);
        
        // Verify the caller is the principal - single check for all authorizations
        assert!(caller == principal, EOnlyPrincipal);
        
        // Single check for valid agent
        assert!(agent != @0x0, EInvalidAgent);
        
        // Process each authorization in the batch
        let i = 0;
        let len = vector::length(&authorizations);
        
        while (i < len) {
            let auth_data = vector::borrow(&authorizations, i);
            
            // Validate authorization parameters
            assert!(auth_data.allowed_calls > 0, EInvalidCalls);
            
            // Validate time range if both are specified
            if (auth_data.start_time != 0 && auth_data.end_time != 0) {
                assert!(auth_data.end_time >= auth_data.start_time, EInvalidTimeRange);
            };
            
            // Create or update the authorization in one step
            let _is_new = create_or_update_function_authorization(
                auth,
                auth_data.function_selector,
                auth_data.start_time,
                auth_data.end_time,
                auth_data.allowed_calls
            );
            
            // Emit event (using cached values where possible)
            event::emit(AgentAuthorized {
                principal,
                agent,
                function_selector: auth_data.function_selector,
                authorization_id: auth_id
            });
            
            i = i + 1;
        };
    }
    
    /// Create a new BatchAuthorizationData struct
    /// @dev Helper function to create batch authorization data
    /// Simplifies the creation of authorization data for batch operations
    /// @param function_selector - The function selector string
    /// @param start_time - Authorization start time (0 = no restriction)
    /// @param end_time - Authorization end time (0 = no restriction)
    /// @param allowed_calls - Number of allowed calls
    /// @return BatchAuthorizationData - The created batch authorization data
    public fun create_batch_authorization_data(
        function_selector: String,
        start_time: u64,
        end_time: u64,
        allowed_calls: u64
    ): BatchAuthorizationData {
        // Validate parameters
        assert!(allowed_calls > 0, EInvalidCalls);
        
        // Optional check: ensure that end_time >= start_time if both are nonzero
        if (start_time != 0 && end_time != 0) {
            assert!(end_time >= start_time, EInvalidTimeRange);
        };
        
        BatchAuthorizationData {
            function_selector,
            start_time,
            end_time,
            allowed_calls
        }
    }
    
    /// Revoke agent authorization for a specific function selector
    /// @dev Removes authorization for a specific function while keeping other authorizations intact
    /// @param auth - The agent authorization object
    /// @param function_selector - The function selector to revoke
    public fun revoke_authorization_for_function(
        auth: &mut AgentAuthorization,
        function_selector: String,
        ctx: &TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        
        // Verify the caller is the principal
        assert!(caller == principal, EOnlyPrincipal);
        
        let function_selector_obj = FunctionSelector { value: function_selector };
        
        // Check if the function is authorized
        assert!(table::contains(&auth.authorized_functions, function_selector_obj), EFunctionNotAuthorized);
        
        // Remove the function authorization
        table::remove(&mut auth.authorized_functions, function_selector_obj);
        
        // Also remove from the tracking vector
        let i = 0;
        let len = vector::length(&auth.function_selectors);
        
        while (i < len) {
            if (vector::borrow(&auth.function_selectors, i).value == function_selector) {
                vector::swap_remove(&mut auth.function_selectors, i);
                break
            };
            i = i + 1;
        };
        
        // Emit event
        event::emit(AgentRevoked {
            principal,
            agent: auth.agent,
            function_selector,
            authorization_id: object::id(auth)
        });
    }
    
    /// Revoke all authorizations for an agent
    /// @dev Completely removes all authorizations for an agent and cleans up registry entries
    /// This removes the agent from all registrations but keeps the authorization object
    /// @param registry - The central registry
    /// @param auth - The agent authorization object
    public fun revoke_all_authorizations(
        registry: &mut Registry,
        auth: &mut AgentAuthorization,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        
        // Verify the caller is the principal
        assert!(caller == principal, EOnlyPrincipal);
        
        let agent = auth.agent;
        
        // Clear all function authorizations directly from the original vector
        // This avoids creating a temporary vector
        while (!vector::is_empty(&auth.function_selectors)) {
            // Always remove from the end to avoid shifting elements
            let selector = vector::pop_back(&mut auth.function_selectors);
            if (table::contains(&auth.authorized_functions, selector)) {
                table::remove(&mut auth.authorized_functions, selector);
            };
        };
        
        // Remove from registry
        if (table::contains(&registry.principal_agent_authorizations, principal)) {
            let principal_agents = table::borrow_mut(&mut registry.principal_agent_authorizations, principal);
            if (table::contains(principal_agents, agent)) {
                // Consume the removed ID
                let _id = table::remove(principal_agents, agent);
            };
        };
        
        // Remove agent from principal mapping
        if (table::contains(&registry.agent_to_principal, agent)) {
            let _principal = table::remove(&mut registry.agent_to_principal, agent);
        };
        
        // Remove from principal's agent list
        if (table::contains(&registry.principal_agents, principal)) {
            let agents_list = table::borrow_mut(&mut registry.principal_agents, principal);
            let i = 0;
            let len = vector::length(agents_list);
            
            // Find and remove the agent from the list
            while (i < len) {
                if (*vector::borrow(agents_list, i) == agent) {
                    vector::swap_remove(agents_list, i);
                    break
                };
                i = i + 1;
            };
        };
        
        // Emit revoke event (generic for all functions)
        event::emit(AgentRevoked {
            principal,
            agent,
            function_selector: string::utf8(b"*"), // Wildcard to indicate all functions
            authorization_id: object::id(auth)
        });
    }
    
    /// Update an existing authorization
    /// @dev Updates time constraints and call limits for an existing function authorization
    /// If the authorization doesn't exist, the function will abort
    /// @param auth - The authorization object to update
    /// @param function_selector - The function selector to update
    /// @param new_start_time - The new start time for the authorization
    /// @param new_end_time - The new end time for the authorization
    /// @param new_allowed_calls - The new allowed calls count
    public fun update_authorization(
        auth: &mut AgentAuthorization,
        function_selector: String,
        new_start_time: u64,
        new_end_time: u64,
        new_allowed_calls: u64,
        ctx: &TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        
        // Verify the caller is the principal
        assert!(caller == principal, EOnlyPrincipal);
        
        assert!(new_allowed_calls > 0, EInvalidCalls);
        
        // Optional check: ensure that end_time >= start_time if both are nonzero
        if (new_start_time != 0 && new_end_time != 0) {
            assert!(new_end_time >= new_start_time, EInvalidTimeRange);
        };
        
        let function_selector_obj = FunctionSelector { value: function_selector };
        
        // Check if the function is authorized
        assert!(table::contains(&auth.authorized_functions, function_selector_obj), EFunctionNotAuthorized);
        
        // Update the authorization data
        let func_auth = table::borrow_mut(&mut auth.authorized_functions, function_selector_obj);
        func_auth.start_time = new_start_time;
        func_auth.end_time = new_end_time;
        func_auth.allowed_calls = new_allowed_calls;
        
        // Emit event
        event::emit(AgentAuthorizationUpdated {
            principal,
            agent: auth.agent,
            function_selector,
            new_start_time,
            new_end_time,
            new_allowed_calls,
            authorization_id: object::id(auth)
        });
    }
    
    /// Check if an agent is authorized for a specific function
    /// @dev Validates all constraints (time bounds and allowed calls) for a function authorization
    /// @param auth - The agent authorization object
    /// @param function_selector - The function selector to check
    /// @param ctx - The transaction context to get timestamp
    /// @return bool - Whether the agent is authorized
    public fun is_authorized_for_function(
        auth: &AgentAuthorization,
        function_selector: String,
        ctx: &TxContext
    ): bool {
        let function_selector_obj = FunctionSelector { value: function_selector };
        
        // Check if the function is authorized
        if (!table::contains(&auth.authorized_functions, function_selector_obj)) {
            return false
        };
        
        let func_auth = table::borrow(&auth.authorized_functions, function_selector_obj);
        
        // Check if allowed calls are available
        if (func_auth.allowed_calls == 0) {
            return false
        };
        
        // Check time constraints
        let now = tx_context::epoch_timestamp_ms(ctx);
        
        // Optimize time constraint checks to fail fast with minimal computations
        if (func_auth.start_time != 0 && now < func_auth.start_time) {
            return false
        };
        
        if (func_auth.end_time != 0 && now > func_auth.end_time) {
            return false
        };
        
        true
    }
    
    /// Function to validate access to a protected resource
    /// @dev Validates if a caller has access to a protected function
    /// Principal always has access, agents need valid authorization
    /// This is the main entry point for access control in the protocol
    /// @param auth - The authorization object to validate
    /// @param function_selector - The function selector to validate
    /// @param ctx - The transaction context
    /// @return bool - Whether access is granted
    public fun validate_access(
        auth: &AgentAuthorization,
        function_selector: String,
        ctx: &TxContext
    ): bool {
        let caller = tx_context::sender(ctx);
        
        // If caller is principal, always grant access (fast path)
        if (caller == auth.principal) {
            return true
        };
        
        // If caller is not the agent, deny immediately (fast path)
        if (caller != auth.agent) {
            return false
        };
        
        // Caller is the agent, check if authorized for this function
        is_authorized_for_function(auth, function_selector, ctx)
    }
    
    /// Decrease allowed calls for a function authorization
    /// @dev Decrements the allowed calls counter after a successful function call
    /// This should be called after successful execution of the authorized function
    /// @param auth - The authorization object to update
    /// @param function_selector - The function selector to decrease calls for
    public fun decrease_allowed_calls(
        auth: &mut AgentAuthorization,
        function_selector: String
    ) {
        let function_selector_obj = FunctionSelector { value: function_selector };
        
        // Optimize by using a direct borrow_mut if the key exists
        if (table::contains(&auth.authorized_functions, function_selector_obj)) {
            let func_auth = table::borrow_mut(&mut auth.authorized_functions, function_selector_obj);
            if (func_auth.allowed_calls > 0) {
                func_auth.allowed_calls = func_auth.allowed_calls - 1;
            };
        };
    }
    
    /// Resolve the principal address for a given address
    /// @dev Helper function to get the principal for any address
    /// If the address is an agent, returns their principal
    /// If the address is not an agent, returns the address itself
    /// @param registry - The central registry
    /// @param addr - The address to resolve
    /// @return address - The principal address
    public fun resolve_principal(registry: &Registry, addr: address): address {
        if (table::contains(&registry.agent_to_principal, addr)) {
            *table::borrow(&registry.agent_to_principal, addr)
        } else {
            addr
        }
    }
    
    /// Check if an address is an agent of another address
    /// @dev Verifies the principal-agent relationship in the registry
    /// @param registry - The central registry
    /// @param principal - The potential principal address
    /// @param agent - The potential agent address
    /// @return bool - Whether the agent is assigned to the principal
    public fun is_agent_of(
        registry: &Registry,
        principal: address,
        agent: address
    ): bool {
        table::contains(&registry.agent_to_principal, agent) && 
        *table::borrow(&registry.agent_to_principal, agent) == principal
    }
    
    /// Get the agent for an authorization
    /// @dev Simple accessor for the agent address in an authorization object
    /// @param auth - The authorization object
    /// @return address - The agent address
    public fun get_agent(auth: &AgentAuthorization): address {
        auth.agent
    }
    
    /// Get the principal for an authorization
    /// @dev Simple accessor for the principal address in an authorization object
    /// @param auth - The authorization object
    /// @return address - The principal address
    public fun get_principal(auth: &AgentAuthorization): address {
        auth.principal
    }
    
    /// Get the remaining allowed calls for a function
    /// @dev Retrieves the current call limit for a specific function
    /// @param auth - The authorization object
    /// @param function_selector - The function selector to check
    /// @return u64 - The number of remaining allowed calls (0 if not authorized)
    public fun get_remaining_calls(
        auth: &AgentAuthorization,
        function_selector: String
    ): u64 {
        let function_selector_obj = FunctionSelector { value: function_selector };
        
        if (table::contains(&auth.authorized_functions, function_selector_obj)) {
            let func_auth = table::borrow(&auth.authorized_functions, function_selector_obj);
            func_auth.allowed_calls
        } else {
            0
        }
    }
    
    /// Get authorization information for all functions authorized for an agent
    /// @dev Returns detailed information about all function authorizations
    /// @param auth - The agent authorization object
    /// @return vector<FunctionAuthorizationInfo> - Vector of authorization details
    public fun get_authorized_functions(
        auth: &AgentAuthorization,
        ctx: &TxContext
    ): vector<FunctionAuthorizationInfo> {
        let caller = tx_context::sender(ctx);
        let principal = auth.principal;
        
        // Verify the caller is the principal or the agent
        assert!(caller == principal || caller == auth.agent, ENotOwnerOrAgent);
        
        let result = vector::empty<FunctionAuthorizationInfo>();
        let i = 0;
        let len = vector::length(&auth.function_selectors);
        
        while (i < len) {
            let selector = vector::borrow(&auth.function_selectors, i);
            let func_auth = table::borrow(&auth.authorized_functions, *selector);
            
            let info = FunctionAuthorizationInfo {
                function_selector: selector.value,
                start_time: func_auth.start_time,
                end_time: func_auth.end_time,
                allowed_calls: func_auth.allowed_calls
            };
            
            vector::push_back(&mut result, info);
            i = i + 1;
        };
        
        result
    }
    
    /// Check if an agent has any authorizations for any functions
    /// @dev Checks if any function authorizations are still valid (active)
    /// Takes into account time constraints and remaining calls
    /// @param auth - The agent authorization object
    /// @param ctx - Transaction context for timestamp
    /// @return bool - Whether the agent has any active authorizations
    public fun has_active_authorizations(auth: &AgentAuthorization, ctx: &TxContext): bool {
        let now = tx_context::epoch_timestamp_ms(ctx);
        let i = 0;
        let len = vector::length(&auth.function_selectors);
        
        while (i < len) {
            let selector = vector::borrow(&auth.function_selectors, i);
            
            // Skip if selector doesn't exist (defensive check)
            if (table::contains(&auth.authorized_functions, *selector)) {
                let func_auth = table::borrow(&auth.authorized_functions, *selector);
                
                if (func_auth.allowed_calls > 0) {
                    // Check time constraints
                    if ((func_auth.start_time == 0 || now >= func_auth.start_time) && 
                        (func_auth.end_time == 0 || now <= func_auth.end_time)) {
                        // Found at least one valid authorization - return immediately
                        return true
                    }
                };
            };
            
            i = i + 1;
        };
        
        false
    }
    
    /// Get all agents for a principal in a module's registry
    /// @dev Returns a vector of all agent addresses authorized by the principal
    /// @param registry - The module's registry
    /// @param principal - The principal address to query
    /// @return vector<address> - Vector of agent addresses for this principal
    public fun get_principal_agents(registry: &Registry, principal: address): vector<address> {
        if (!table::contains(&registry.principal_agents, principal)) {
            return vector::empty<address>()
        };
        
        // Return a copy of the agents list for this principal
        *table::borrow(&registry.principal_agents, principal)
    }
    
    /// Get the principal for an agent in a module's registry
    /// @dev Checks if an address is registered as an agent and returns its principal
    /// @param registry - The module's registry
    /// @param agent - The agent address to query
    /// @return (bool, address) - (exists, principal) - If no principal exists, returns (false, @0x0)
    public fun get_agent_principal(registry: &Registry, agent: address): (bool, address) {
        if (table::contains(&registry.agent_to_principal, agent)) {
            (true, *table::borrow(&registry.agent_to_principal, agent))
        } else {
            (false, @0x0)
        }
    }
    
    /// Check if an AgentAuthorization is registered under a given registry
    /// @dev Verifies if the authorization object is properly registered in the registry's mappings
    /// @param registry - The registry to check against
    /// @param auth - The authorization object to verify
    /// @return bool - Whether the authorization is properly registered
    public fun is_authorization_registered(
        registry: &Registry,
        auth: &AgentAuthorization
    ): bool {
        let principal = auth.principal;
        let agent = auth.agent;
        let auth_id = object::id(auth);

        // Check if the principal has any agent authorizations
        if (!table::contains(&registry.principal_agent_authorizations, principal)) {
            return false
        };

        // Check if the agent is registered to this principal
        let principal_agents = table::borrow(&registry.principal_agent_authorizations, principal);
        if (!table::contains(principal_agents, agent)) {
            return false
        };

        // Check if the stored authorization ID matches
        let stored_auth_id = table::borrow(principal_agents, agent);
        auth_id == *stored_auth_id
    }
    
    // ===== Test helpers =====
    
    #[test_only]
    /// Create a new table for testing purposes
    public fun test_new_table<K: copy + drop + store, V: store>(ctx: &mut TxContext): Table<K, V> {
        table::new<K, V>(ctx)
    }
    
    #[test_only]
    /// Create a Registry for testing
    public fun test_create_registry(ctx: &mut TxContext): Registry {
        Registry {
            id: object::new(ctx),
            agent_to_principal: table::new(ctx),
            principal_agent_authorizations: table::new(ctx),
            principal_agents: table::new(ctx)
        }
    }
    
    #[test_only]
    /// Create and share a Registry for testing
    public fun test_create_and_share_registry(ctx: &mut TxContext) {
        let registry = test_create_registry(ctx);
        transfer::share_object(registry);
    }
    
    #[test_only]
    /// Initialize the test environment
    public fun test_init_environment(_scenario: &mut Scenario) {
        // No initialization needed now that we don't have a lookup table
    }
    
    #[test_only]
    /// Test the module registry functionality with the new architecture
    public fun test_module_registry(scenario: &mut Scenario) {
        // Module creates its own registry
        ts::next_tx(scenario, @0xAA);
        {
            // Create registry object owned by module
            let registry = create_module_registry(ts::ctx(scenario));
            
            // Return registry to sender (simulates module ownership)
            ts::return_to_sender(scenario, registry);
        };
        
        // Module uses its registry to create an agent authorization
        ts::next_tx(scenario, @0xAA);
        {
            let registry = ts::take_from_sender<Registry>(scenario);
            
            // Create an agent authorization
            let auth_id = create_agent_with_authorization(
                &mut registry,
                @0xCC, // agent
                string::utf8(b"module_function"),
                0, 0, 5, // no time restrictions, 5 calls
                ts::ctx(scenario)
            );
            
            // Print authorization ID for reference
            std::debug::print(&auth_id);
            
            // Return registry to sender
            ts::return_to_sender(scenario, registry);
            // Authorization is shared
        };
        
        // Module uses its registry to validate access
        ts::next_tx(scenario, @0xAA);
        {
            let registry = ts::take_from_sender<Registry>(scenario);
            let auth = ts::take_shared<AgentAuthorization>(scenario);
            
            // Validate access (using the validate_access function directly since registry is owned)
            assert!(
                validate_access(&auth, string::utf8(b"module_function"), ts::ctx(scenario)),
                1000
            );
            
            // Return registry to sender
            ts::return_to_sender(scenario, registry);
            ts::return_shared(auth);
        };
        
        // Another module creates its own registry
        ts::next_tx(scenario, @0xBB);
        {
            // Create registry for module B
            let registry = create_module_registry(ts::ctx(scenario));
            
            // Return registry to sender (simulates module ownership)
            ts::return_to_sender(scenario, registry);
        };
    }
    
    #[test_only]
    /// Create an empty agent authorization for testing
    public fun create_empty_agent_auth_for_testing(
        _registry: &mut Registry, 
        principal: address, 
        ctx: &mut TxContext
    ): AgentAuthorization {
        AgentAuthorization {
            id: object::new(ctx),
            principal,
            agent: principal, // Self-authorization
            authorized_functions: table::new(ctx),
            function_selectors: vector::empty<FunctionSelector>()
        }
    }
    
    #[test_only]
    /// Create an empty agent authorization and share it (for testing)
    public fun create_and_share_agent_auth_for_testing(
        _registry: &mut Registry, 
        principal: address, 
        ctx: &mut TxContext
    ) {
        let auth = AgentAuthorization {
            id: object::new(ctx),
            principal,
            agent: principal, // Self-authorization
            authorized_functions: table::new(ctx),
            function_selectors: vector::empty<FunctionSelector>()
        };
        
        transfer::share_object(auth);
    }
    
    #[test_only]
    /// Transfer an agent authorization to a recipient (test only)
    public fun transfer_auth_for_testing(auth: AgentAuthorization, recipient: address) {
        transfer::transfer(auth, recipient);
    }
    
    #[test_only]
    /// Set the agent field in an authorization object (for testing)
    public fun test_set_agent_for_auth(auth: &mut AgentAuthorization, agent: address) {
        auth.agent = agent;
    }
} 