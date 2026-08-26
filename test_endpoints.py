import requests, json

base = 'https://nhxymqfpweywwylxmuju.supabase.co'

# Test GraphQL endpoint
r = requests.post(f'{base}/graphql/v1/graphql', 
    json={'query': '{ __typename { __schema { types { name } } } }'},
    timeout=5)
print(f'GraphQL: {r.status_code} - {r.text[:150]}')

# Test for debug/verbose error messages
r2 = requests.get(f'{base}/rest/v1/users?select=*', 
    headers={'apikey': 'faketestkey', 'Authorization': 'Bearer faketestkey'},
    timeout=5)
print(f'Fake key: {r2.status_code} - {r2.text[:150]}')

# Test for edge functions
r3 = requests.get(f'{base}/functions/v1/', timeout=5)
print(f'Edge functions list: {r3.status_code} - {r3.text[:150]}')

# Test for storage API
r4 = requests.get(f'{base}/storage/v1/buckets', timeout=5)
print(f'Storage buckets: {r4.status_code} - {r4.text[:150]}')

# Test database directly
r5 = requests.get(f'{base}/rest/v1/', timeout=5)
print(f'Rest root: {r5.status_code} - {r5.text[:150]}')

# Check for version info
r6 = requests.get(f'{base}/rest/v1/', headers={'apikey': 'test'}, timeout=5)
print(f'Version/headers: {r6.status_code}')
for k,v in r6.headers.items():
    print(f'  {k}: {v}')
