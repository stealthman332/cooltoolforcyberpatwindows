import sys
sys.path.insert(0, '.')

try:
    from collectors import get_local_policy
    
    result = get_local_policy()
    
    if isinstance(result, dict):
        print('=== Result Summary ===')
        print(f'Error field: {repr(result.get("Error"))}')
        print(f'NonDefaultCount: {result.get("NonDefaultCount")}')
        print(f'AllPolicies count: {len(result.get("AllPolicies", []))}')
        print(f'Policies count: {len(result.get("Policies", []))}')
        
        print('\n=== First Few Policies (Non-Default) ===')
        policies = result.get('Policies', [])
        for i, policy in enumerate(policies[:3]):
            print(f'Policy {i+1}: {policy}')
        
        print('\n=== Sample AllPolicies ===')
        all_policies = result.get('AllPolicies', [])
        for i, policy in enumerate(all_policies[:3]):
            print(f'Policy {i+1}: {policy}')
    
except Exception as e:
    print(f'Error occurred: {type(e).__name__}: {str(e)}')
    import traceback
    traceback.print_exc()
