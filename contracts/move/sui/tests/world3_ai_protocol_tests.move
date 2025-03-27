#[allow(unused_use)]
module world3_ai_protocol::world3_ai_protocol_tests {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::object;
    use sui::transfer;
    use std::string;
    use std::vector;

    use world3_ai_protocol::world3_ai_protocol::{
        Self as Protocol,
        Registry,
        AgentAuthorization,
        BatchAuthorizationData
    };

    // Test addresses
    const ADMIN: address = @0xA1;
    const PRINCIPAL: address = @0xB1;
    const AGENT: address = @0xC1;
    const NON_AUTHORIZED: address = @0xD1;

    // Test function selectors
    const FUNCTION_A: vector<u8> = b"functionA";
    const FUNCTION_B: vector<u8> = b"functionB";
    #[allow(unused_const)]
    const FUNCTION_C: vector<u8> = b"functionC";

    // Error codes from the main module - using only what's needed
    const EInvalidCalls: u64 = 1;
    const EInvalidTimeRange: u64 = 2;

    // ===== Test initialization =====

    fun setup_test(): Scenario {
        let scenario = ts::begin(ADMIN);
        // Create and share registry
        ts::next_tx(&mut scenario, ADMIN);
        {
            // Use the protocol's function to create and share the registry
            Protocol::test_create_and_share_registry(ts::ctx(&mut scenario));
        };
        scenario
    }

    #[test_only]
    fun test_environment_setup(scenario: &mut Scenario) {
        Protocol::test_init_environment(scenario);
    }

    // ===== Test cases =====

    #[test]
    fun test_create_agent_with_authorization() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create an agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            let function_selector = string::utf8(FUNCTION_A);
            let start_time = 0; // No start time restriction
            let end_time = 0;   // No end time restriction
            let allowed_calls = 5;
            
            let auth_id = Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                function_selector,
                start_time,
                end_time,
                allowed_calls,
                ts::ctx(&mut scenario)
            );
            
            // Verify auth_id is not null
            assert!(object::id_to_address(&auth_id) != @0x0, 0);
            
            ts::return_shared(registry);
        };
        
        // Verify the authorization exists and has correct properties
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Check principal and agent are set correctly
            assert!(Protocol::get_principal(&auth) == PRINCIPAL, 1);
            assert!(Protocol::get_agent(&auth) == AGENT, 2);
            
            // Check agent is registered with principal
            assert!(Protocol::is_agent_of(&registry, PRINCIPAL, AGENT), 3);
            
            // Check the function is authorized
            let function_selector = string::utf8(FUNCTION_A);
            assert!(Protocol::is_authorized_for_function(&auth, function_selector, ts::ctx(&mut scenario)), 4);
            
            // Check remaining calls
            assert!(Protocol::get_remaining_calls(&auth, function_selector) == 5, 5);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = EInvalidCalls, location = world3_ai_protocol::world3_ai_protocol)]
    fun test_create_agent_with_zero_calls() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Attempt to create with 0 allowed calls (should fail)
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, // start_time
                0, // end_time
                0, // allowed_calls - this should cause failure
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = EInvalidTimeRange, location = world3_ai_protocol::world3_ai_protocol)]
    fun test_invalid_time_range() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Attempt to create with end_time < start_time (should fail)
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                1000, // start_time
                500,  // end_time - this should cause failure as it's less than start_time
                5,    // allowed_calls
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_authorize_agent_for_new_function() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // First create agent with authorization for functionA
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Now authorize for functionB
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            Protocol::authorize_agent(
                &mut registry,
                &mut auth,
                string::utf8(FUNCTION_B),
                0, 0, 10,
                ts::ctx(&mut scenario)
            );
            
            // Verify both functions are authorized
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 1);
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 2);
            
            // Check remaining calls
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 5, 3);
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_B)) == 10, 4);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_update_authorization() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // First create agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Now update the authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            Protocol::update_authorization(
                &mut auth,
                string::utf8(FUNCTION_A),
                100, // new start_time
                200, // new end_time
                20,  // new allowed_calls
                ts::ctx(&mut scenario)
            );
            
            // Check updated values
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 20, 1);
            
            // Since we can't directly access fields of FunctionAuthorizationInfo, 
            // we'll just check that we can get the authorized functions without error
            let _auth_info_vec = Protocol::get_authorized_functions(&auth, ts::ctx(&mut scenario));
            // We can't check the specific fields because of visibility restrictions
            
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_validate_access() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Test access validation from principal (should always be allowed)
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Principal should be allowed for any function
            assert!(Protocol::validate_access(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 1);
            assert!(Protocol::validate_access(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 2);
            
            ts::return_shared(auth);
        };
        
        // Test access validation from agent (should only be allowed for authorized functions)
        ts::next_tx(&mut scenario, AGENT);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Agent should be allowed for functionA but not functionB
            assert!(Protocol::validate_access(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 3);
            assert!(!Protocol::validate_access(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 4);
            
            ts::return_shared(auth);
        };
        
        // Test access validation from non-authorized account
        ts::next_tx(&mut scenario, NON_AUTHORIZED);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Non-authorized account should not be allowed for any function
            assert!(!Protocol::validate_access(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 5);
            assert!(!Protocol::validate_access(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 6);
            
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_decrease_allowed_calls() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Decrease allowed calls
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Check initial calls
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 5, 1);
            
            // Decrease calls
            Protocol::decrease_allowed_calls(&mut auth, string::utf8(FUNCTION_A));
            
            // Check after first decrease
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 4, 2);
            
            // Decrease multiple times
            Protocol::decrease_allowed_calls(&mut auth, string::utf8(FUNCTION_A));
            Protocol::decrease_allowed_calls(&mut auth, string::utf8(FUNCTION_A));
            
            // Check after multiple decreases
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 2, 3);
            
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_resolve_principal() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            // Test resolve_principal function
            // For agent
            assert!(Protocol::resolve_principal(&registry, AGENT) == PRINCIPAL, 1);
            
            // For principal (should return self)
            assert!(Protocol::resolve_principal(&registry, PRINCIPAL) == PRINCIPAL, 2);
            
            // For non-agent (should return self)
            assert!(Protocol::resolve_principal(&registry, NON_AUTHORIZED) == NON_AUTHORIZED, 3);
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_get_authorized_functions() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with multiple authorizations
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Add second function
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            Protocol::authorize_agent(
                &mut registry,
                &mut auth,
                string::utf8(FUNCTION_B),
                0, 0, 10,
                ts::ctx(&mut scenario)
            );
            
            // Get authorized functions
            let auth_functions = Protocol::get_authorized_functions(&auth, ts::ctx(&mut scenario));
            
            // Verify we have 2 functions
            assert!(vector::length(&auth_functions) == 2, 1);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_has_active_authorizations() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Check active authorizations
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Should have active authorizations
            assert!(Protocol::has_active_authorizations(&auth, ts::ctx(&mut scenario)), 1);
            
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_revoke_authorization_for_function() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with multiple authorizations
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Add second function
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            Protocol::authorize_agent(
                &mut registry,
                &mut auth,
                string::utf8(FUNCTION_B),
                0, 0, 10,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        // Revoke the first function
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Check initial state
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 1);
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 2);
            
            Protocol::revoke_authorization_for_function(
                &mut auth,
                string::utf8(FUNCTION_A),
                ts::ctx(&mut scenario)
            );
            
            // Verify first function is no longer authorized
            assert!(!Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 3);
            
            // Verify second function is still authorized
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 4);
            
            ts::return_shared(auth);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_revoke_all_authorizations() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent with multiple authorizations
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Add more functions with batch authorization
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            let authorizations = vector::empty<BatchAuthorizationData>();
            vector::push_back(&mut authorizations, Protocol::create_batch_authorization_data(
                string::utf8(FUNCTION_B), 0, 0, 10
            ));
            vector::push_back(&mut authorizations, Protocol::create_batch_authorization_data(
                string::utf8(FUNCTION_C), 0, 0, 15
            ));
            
            Protocol::batch_authorize_agent(
                &mut registry,
                &mut auth,
                authorizations,
                ts::ctx(&mut scenario)
            );
            
            // Verify initial state
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 1);
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 2);
            
            // Check agent registration
            assert!(Protocol::is_agent_of(&registry, PRINCIPAL, AGENT), 3);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        // Revoke all authorizations
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            Protocol::revoke_all_authorizations(
                &mut registry,
                &mut auth,
                ts::ctx(&mut scenario)
            );
            
            // Verify all functions are revoked
            assert!(!Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 4);
            assert!(!Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 5);
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_C)) == 0, 6);
            
            // Agent should no longer be registered
            assert!(!Protocol::is_agent_of(&registry, PRINCIPAL, AGENT), 7);
            
            // Check if has_active_authorizations returns false
            assert!(!Protocol::has_active_authorizations(&auth, ts::ctx(&mut scenario)), 8);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_get_principal_agents() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create first agent
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            // Initially should have one agent
            let agents = Protocol::get_principal_agents(&registry, PRINCIPAL);
            assert!(vector::length(&agents) == 1, 1);
            assert!(*vector::borrow(&agents, 0) == AGENT, 2);
            
            ts::return_shared(registry);
        };
        
        // Create second agent
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                NON_AUTHORIZED, // Using as second agent
                string::utf8(FUNCTION_B),
                0, 0, 10,
                ts::ctx(&mut scenario)
            );
            
            // Now should have two agents
            let agents = Protocol::get_principal_agents(&registry, PRINCIPAL);
            assert!(vector::length(&agents) == 2, 3);
            
            // Agents can be in any order, so check both exist
            let has_agent1 = false;
            let has_agent2 = false;
            
            let i = 0;
            let len = vector::length(&agents);
            while (i < len) {
                let agent = *vector::borrow(&agents, i);
                if (agent == AGENT) {
                    has_agent1 = true;
                };
                if (agent == NON_AUTHORIZED) {
                    has_agent2 = true;
                };
                i = i + 1;
            };
            
            assert!(has_agent1, 4);
            assert!(has_agent2, 5);
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }

    #[test]
    fun test_batch_authorize_agent() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // First create agent with authorization for functionA
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Now batch authorize for functionB and functionC
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            let auth = ts::take_shared<AgentAuthorization>(&scenario);
            
            // Create batch authorization data
            let authorizations = vector::empty<BatchAuthorizationData>();
            
            vector::push_back(
                &mut authorizations, 
                Protocol::create_batch_authorization_data(
                    string::utf8(FUNCTION_B),
                    0, 0, 10
                )
            );
            
            vector::push_back(
                &mut authorizations, 
                Protocol::create_batch_authorization_data(
                    string::utf8(FUNCTION_C),
                    100, 200, 15
                )
            );
            
            // Perform batch authorization
            Protocol::batch_authorize_agent(
                &mut registry,
                &mut auth,
                authorizations,
                ts::ctx(&mut scenario)
            );
            
            // Verify all functions are authorized
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_A), ts::ctx(&mut scenario)), 1);
            assert!(Protocol::is_authorized_for_function(&auth, string::utf8(FUNCTION_B), ts::ctx(&mut scenario)), 2);
            
            // FUNCTION_C has a time restriction, so we can't verify it's authorized without setting the epoch time
            // Instead, just check that it has the expected number of calls
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_C)) == 15, 3);
            
            // Check remaining calls
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_A)) == 5, 4);
            assert!(Protocol::get_remaining_calls(&auth, string::utf8(FUNCTION_B)) == 10, 5);
            
            ts::return_shared(auth);
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }
    
    #[test]
    fun test_get_agent_principal() {
        let scenario = setup_test();
        test_environment_setup(&mut scenario);
        
        // Create agent
        ts::next_tx(&mut scenario, PRINCIPAL);
        {
            let registry = ts::take_shared<Registry>(&scenario);
            
            Protocol::create_agent_with_authorization(
                &mut registry,
                AGENT,
                string::utf8(FUNCTION_A),
                0, 0, 5,
                ts::ctx(&mut scenario)
            );
            
            // Test get_agent_principal
            let (exists, principal) = Protocol::get_agent_principal(&registry, AGENT);
            assert!(exists, 1);
            assert!(principal == PRINCIPAL, 2);
            
            // Test for non-agent address
            let (exists, principal) = Protocol::get_agent_principal(&registry, NON_AUTHORIZED);
            assert!(!exists, 3);
            assert!(principal == @0x0, 4);
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }
} 