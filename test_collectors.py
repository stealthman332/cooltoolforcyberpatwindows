import sys
sys.path.insert(0, '.')

try:
    from collectors import get_local_policy
    print('Successfully imported get_local_policy')
    
    result = get_local_policy()
    print(f'Type of result: {type(result)}')
    
    if isinstance(result, dict):
        print(f'Result keys: {list(result.keys())}')
        print(f'Error: {result.get("Error")}')
        
        policies = result.get('Policies', {})
        print(f'Policies count: {len(policies) if isinstance(policies, dict) else "N/A"}')
        print(f'NonDefaultCount: {result.get("NonDefaultCount")}')
        
        print('\nFull result structure:')
        for key, value in result.items():
            if isinstance(value, dict):
                print(f'  {key}: dict with {len(value)} items')
            elif isinstance(value, (list, tuple)):
                print(f'  {key}: {type(value).__name__} with {len(value)} items')
            else:
                print(f'  {key}: {value}')
    else:
        print(f'Result is not a dict: {result}')
    
except Exception as e:
    print(f'Error occurred: {type(e).__name__}: {str(e)}')
    import traceback
    traceback.print_exc()
