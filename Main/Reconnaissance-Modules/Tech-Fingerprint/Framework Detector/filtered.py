import json, urllib.request

CATS = {1, 16, 18, 12, 44, 3,9,22,27,33,46,59,69,80,87,4,28,31,81,82,100 }   # CMS, Security, WebFW, JS-FW, JS-lib, UI-FW

src = json.loads(urllib.request.urlopen(
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/z.json"
).read().decode())

names = sorted(name for name, t in src.items()
               if any(c in CATS for c in t.get("cats", [])))

print(f"Cəmi: {len(names)} texnologiya\n")
for n in names:
    print(n)