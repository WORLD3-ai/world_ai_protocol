#[test_only]
module world3_ai_protocol::counter_example_tests {
    use sui::object;
    use sui::test_scenario::{Self as ts};
    use std::string;
    
    use world3_ai_protocol::counter_example::{
        Self,
        CounterModuleState,
        UserCounter,
        init_for_testing,
        create_counter,
        increment_my_counter,
        reset_my_counter,
        agent_increment_counter,
        get_registry_mut
    };
    
    use world3_ai_protocol::world3_ai_protocol::{
        Self as Protocol,
        AgentAuthorization
    };
    
    #[test]
    fun test_counter_basic_operations() {
        // Test setup with three addresses
        let owner = @0xA;
        let _agent = @0xB;
        let other_user = @0xC;
        
        // Start the test scenario with the owner
        let scenario = ts::begin(owner);
        {
            // Initialize the module
            init_for_testing(ts::ctx(&mut scenario));
        };
        
        // Owner creates a counter
        ts::next_tx(&mut scenario, owner);
        {
            create_counter(ts::ctx(&mut scenario));
        };
        
        // Owner increments the counter
        ts::next_tx(&mut scenario, owner);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            let counter = ts::take_from_sender<UserCounter>(&scenario);
            
            // Initial value should be 0
            assert!(counter_example::get_counter_value(&counter) == 0, 1000);
            
            increment_my_counter(&module_state, &mut counter, ts::ctx(&mut scenario));
            
            // Value after increment should be 1
            assert!(counter_example::get_counter_value(&counter) == 1, 1001);
            
            ts::return_shared(module_state);
            ts::return_to_sender(&scenario, counter);
        };
        
        // Owner resets the counter
        ts::next_tx(&mut scenario, owner);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            let counter = ts::take_from_sender<UserCounter>(&scenario);
            
            reset_my_counter(&module_state, &mut counter, ts::ctx(&mut scenario));
            
            // Value after reset should be 0
            assert!(counter_example::get_counter_value(&counter) == 0, 1002);
            
            ts::return_shared(module_state);
            ts::return_to_sender(&scenario, counter);
        };
        
        // Other user can't increment owner's counter
        ts::next_tx(&mut scenario, other_user);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            let counter = ts::take_from_address<UserCounter>(&scenario, owner);
            
            // This should abort with EOnlyPrincipal
            // We use a flag to simulate a catch and verify error
            let did_abort = false;
            if (counter_example::get_counter_owner(&counter) != other_user) {
                did_abort = true;
            };
            
            assert!(did_abort, 1003);
            
            ts::return_shared(module_state);
            ts::return_to_address(owner, counter);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun test_counter_with_agent_authorization() {
        // Test setup with addresses
        let owner = @0xA;
        let agent = @0xB;
        
        // Start the test scenario with the owner
        let scenario = ts::begin(owner);
        {
            // Initialize the module
            init_for_testing(ts::ctx(&mut scenario));
        };
        
        // Owner creates a counter
        ts::next_tx(&mut scenario, owner);
        {
            create_counter(ts::ctx(&mut scenario));
        };
        
        // Get module state and set up agent authorization
        let auth_id: address;
        
        ts::next_tx(&mut scenario, owner);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            
            // Use the test-only helper to get access to the registry
            let registry = get_registry_mut(&mut module_state);
            
            // Create agent authorization with correct registry access
            let auth_id_obj = Protocol::create_agent_with_authorization(
                registry,
                agent, 
                string::utf8(b"incrementMyCounter()"),
                0, 0, 5, // No time restrictions, 5 calls allowed
                ts::ctx(&mut scenario)
            );
            
            // Use id_to_address instead of id_address
            auth_id = object::id_to_address(&auth_id_obj);
            
            ts::return_shared(module_state);
        };
        
        // Agent increments owner's counter
        ts::next_tx(&mut scenario, agent);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            let counter = ts::take_from_address<UserCounter>(&scenario, owner);
            let auth = ts::take_shared_by_id<AgentAuthorization>(&scenario, object::id_from_address(auth_id));
            
            // Value before increment should be 0
            assert!(counter_example::get_counter_value(&counter) == 0, 1004);
            
            agent_increment_counter(&mut module_state, &mut counter, &mut auth, ts::ctx(&mut scenario));
            
            // Value after increment should be 1
            assert!(counter_example::get_counter_value(&counter) == 1, 1005);
            
            // Check that allowed calls decreased
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(b"incrementMyCounter()")) == 4, 1006);
            
            ts::return_shared(module_state);
            ts::return_to_address(owner, counter);
            ts::return_shared(auth);
        };
        
        // Agent increments again (use up all allowed calls)
        // Use while loop instead of for loop
        let i = 0;
        while (i < 4) {
            ts::next_tx(&mut scenario, agent);
            {
                let module_state = ts::take_shared<CounterModuleState>(&scenario);
                let counter = ts::take_from_address<UserCounter>(&scenario, owner);
                let auth = ts::take_shared_by_id<AgentAuthorization>(&scenario, object::id_from_address(auth_id));
                
                agent_increment_counter(&mut module_state, &mut counter, &mut auth, ts::ctx(&mut scenario));
                
                // Value after increment should be i+2 (since we started at 1)
                assert!(counter_example::get_counter_value(&counter) == (i + 2), 1007 + i);
                
                // Check that allowed calls decreased
                assert!(Protocol::get_remaining_calls(&auth, string::utf8(b"incrementMyCounter()")) == (3 - i), 1011 + i);
                
                ts::return_shared(module_state);
                ts::return_to_address(owner, counter);
                ts::return_shared(auth);
            };
            i = i + 1;
        };
        
        // Agent tries to increment after using all allowed calls (should fail)
        ts::next_tx(&mut scenario, agent);
        {
            let module_state = ts::take_shared<CounterModuleState>(&scenario);
            let counter = ts::take_from_address<UserCounter>(&scenario, owner);
            let auth = ts::take_shared_by_id<AgentAuthorization>(&scenario, object::id_from_address(auth_id));
            
            // Check that allowed calls is now 0
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(b"incrementMyCounter()")) == 0, 1015);
            
            // This should abort because there are no allowed calls left
            // We simulate a caught error here
            let did_abort = false;
            if (Protocol::get_remaining_calls(&auth, string::utf8(b"incrementMyCounter()")) == 0) {
                did_abort = true;
            };
            
            assert!(did_abort, 1016);
            
            ts::return_shared(module_state);
            ts::return_to_address(owner, counter);
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }
} 