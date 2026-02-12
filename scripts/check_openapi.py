import urllib.request

url = 'http://127.0.0.1:8000/openapi.json'
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as r:
    print(r.status)
    print(r.read(200).decode('utf-8', errors='replace'))
