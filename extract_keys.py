import re
import base64

with open('C:/Users/HomePC/AppData/Local/Temp/blink_main_check.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Get exact context around the anon key usage
idx = content.find('OCqzmAsdlSeHbUYc0cxzZdySf0jm-FkQ-U_1Kfg5rAM')
if idx > 0:
    context = content[idx-300:idx+300]
    print('Key context:')
    print(repr(context))

# Look for Supabase URL patterns
for m in re.finditer(r'supabase\.co', content):
    start = max(0, m.start()-50)
    end = min(len(content), m.end()+50)
    print('Found supabase at:', content[start:end])
