import httpx, json

token = "eyJraWQiOiJldS1jZW50cmFsLTEtcHJvZC0wIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJzZXJ2aWNldXNlci1hMzlmMGE3My1jOTFkLTQwYjgtODRjOS02ZTMwMzZmNTMxODhAbWdtdC0xNDQxNS5zZW50aW5lbG9uZS5uZXQiLCJpc3MiOiJhdXRobi1ldS1jZW50cmFsLTEtcHJvZCIsImRlcGxveW1lbnRfaWQiOiIxNDQxNSIsInR5cGUiOiJ1c2VyIiwiZXhwIjoxNzgyMzMyOTcwLCJpYXQiOjE3NzQzODQzMDksImp0aSI6IjFjYzliNTAwLWZkYmMtNGE1Zi1iMDJmLWNjZjY1NzBmZWYzMSJ9.pSX_xsP5lJNOg-w8OZVAk8HQ95HfACFA9tbV8faxEkP70BjLWy8bX009YGOJGFWqdxe-dPsDIr9-g2eFJAEbVg"
base = "https://euce1-exclusive.sentinelone.net"

r = httpx.get(
    f"{base}/web/api/v2.1/threats",
    headers={"Authorization": f"ApiToken {token}"},
    params={"limit": 1, "sortBy": "createdAt", "sortOrder": "desc"},
    timeout=30,
    follow_redirects=True,
)
print("HTTP", r.status_code)
if r.status_code == 200:
    data = r.json().get("data", [])
    if data:
        t = data[0]
        ti = t.get("threatInfo", {})
        ari = t.get("agentRealtimeInfo", {})
        print("=== threatInfo ===")
        print(json.dumps(ti, indent=2))
        print()
        print("=== agentRealtimeInfo ===")
        print(json.dumps(ari, indent=2))
    else:
        print("No threats returned")
else:
    print(r.text[:800])
