import re

with open('C:/Users/HomePC/AppData/Local/Temp/blink_main_check.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the createClient initialization code
idx = content.find('createClient')
if idx >= 0:
    # Get 3000 chars around it
    context = content[max(0, idx-500):idx+3000]
    print("=== Context around createClient ===")
    print(context[:500])
    print("\n=== Searching for potential secrets ===")
    
    # Find any quoted strings that look like secrets (long base64, hex strings)
    secrets = re.findall(r'["\']([A-Za-z0-9+/=_\-]{40,})["\']', context)
    for s in set(secrets):
        print(f'Potential secret: {s[:80]}')

# Also look near supabase reference
idx2 = content.find('supabase.co')
if idx2 >= 0:
    context2 = content[max(0, idx2-200):idx2+1000]
    secrets2 = re.findall(r'["\']([A-Za-z0-9+/=_\-]{40,})["\']', context2)
    for s in set(secrets2):
        print(f'Near supabase URL: {s[:80]}')

# Also search for jwt-secret keyword or variable
for m in re.finditer(r'jwt[a-zA-Z_-]*', content, re.IGNORECASE):
    start = max(0, m.start()-100)
    end = min(len(content), m.end()+100)
    context = content[start:end]
    if 'secret' in context.lower() or 'key' in context.lower():
        print(f'\nFound JWT context: {context}')
