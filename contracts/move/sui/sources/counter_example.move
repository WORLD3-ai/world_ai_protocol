module world3_ai_protocol::counter_example {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use std::string;
    
    use world3_ai_protocol::world3_ai_protocol::{
        Self as Protocol,
        Registry,
        AgentAuthorization
    };
    
    /// Error codes
    const EOnlyPrincipal: u64 = 100;
    const EAuthNotRegistered: u64 = 101;
    const ECounterNotFound: u64 = 102;
    
    /// Wrapper for the Counter module that owns the protocol registry
    struct CounterModuleState has key {
        id: UID,
        /// The Registry object for authorization
        registry: Registry
    }
    
    /// Per-user counter data, owned by the user
    struct UserCounter has key {
        id: UID,
        /// The owner's address
        owner: address,
        /// The counter value
        value: u64
    }
    
    /// Events
    struct CounterIncremented has copy, drop {
        principal: address,
        new_value: u64
    }
    
    struct CounterReset has copy, drop {
        principal: address
    }
    
    struct CounterCreated has copy, drop {
        owner: address,
        counter_id: address
    }
    
    /// Module initialization creates a module-specific registry and wrapper
    fun init(ctx: &mut TxContext) {
        // Create a protocol registry for this module
        let registry = Protocol::create_module_registry(ctx);
        
        // Create the module state that owns the registry
        let module_state = CounterModuleState {
            id: object::new(ctx),
            registry
        };
        
        // Share the module state
        transfer::share_object(module_state);
    }
    
    /// Create a new counter for the caller
    public entry fun create_counter(ctx: &mut TxContext) {
        let owner = tx_context::sender(ctx);
        
        // Create counter object for the owner
        let counter = UserCounter {
            id: object::new(ctx),
            owner,
            value: 0
        };
        
        let counter_id = object::id_address(&counter);
        
        // Emit creation event
        event::emit(CounterCreated {
            owner,
            counter_id
        });
        
        // Transfer counter to the owner
        transfer::transfer(counter, owner);
    }
    
    /// Increment the user's counter by 1
    /// Only the counter owner can call this function
    public entry fun increment_my_counter(
        _module_state: &CounterModuleState,
        counter: &mut UserCounter,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        
        // Ensure caller is the counter owner
        assert!(caller == counter.owner, EOnlyPrincipal);
        
        // Increment counter
        counter.value = counter.value + 1;
        
        // Emit event
        event::emit(CounterIncremented {
            principal: caller,
            new_value: counter.value
        });
    }
    
    /// Increment the principal's counter using agent authorization
    /// Can be called by either the principal or an authorized agent
    public entry fun agent_increment_counter(
        module_state: &mut CounterModuleState,
        counter: &mut UserCounter,
        auth: &mut AgentAuthorization,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        let function_selector = string::utf8(b"incrementMyCounter()");
        
        // Ensure counter is accessed by either owner or authorized agent
        if (caller != counter.owner) {
            // Resolve the actual principal (owner) based on the caller
            let actual_owner = Protocol::resolve_principal(&module_state.registry, caller);
            
            // Ensure counter belongs to the resolved principal
            assert!(counter.owner == actual_owner, ECounterNotFound);
            
            // First verify that this authorization belongs to our registry
            assert!(
                Protocol::is_authorization_registered(&module_state.registry, auth),
                EAuthNotRegistered
            );

            // Then check if the agent is authorized for this function
            assert!(
                Protocol::validate_access(auth, function_selector, ctx),
                EOnlyPrincipal
            );
            
            // Decrease allowed calls after successful validation
            Protocol::decrease_allowed_calls(auth, function_selector);
        };
        
        // Increment counter
        counter.value = counter.value + 1;
        
        // Emit event
        event::emit(CounterIncremented {
            principal: counter.owner,
            new_value: counter.value
        });
    }
    
    /// Reset the principal's counter to zero
    /// Can only be called by the counter owner
    public entry fun reset_my_counter(
        _module_state: &CounterModuleState,
        counter: &mut UserCounter,
        ctx: &mut TxContext
    ) {
        let caller = tx_context::sender(ctx);
        
        // Ensure caller is the counter owner
        assert!(caller == counter.owner, EOnlyPrincipal);
        
        // Reset counter
        counter.value = 0;
        
        // Emit event
        event::emit(CounterReset {
            principal: caller
        });
    }
    
    /// Get the counter value
    public fun get_counter_value(counter: &UserCounter): u64 {
        counter.value
    }
    
    /// Get the counter owner
    public fun get_counter_owner(counter: &UserCounter): address {
        counter.owner
    }
    
    // === Test helpers ===
    
    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx)
    }
    
    /// Get a reference to the registry for testing
    #[test_only]
    public fun get_registry_ref(module_state: &CounterModuleState): &Registry {
        &module_state.registry
    }
    
    /// Get a mutable reference to the registry for testing
    #[test_only]
    public fun get_registry_mut(module_state: &mut CounterModuleState): &mut Registry {
        &mut module_state.registry
    }
} 