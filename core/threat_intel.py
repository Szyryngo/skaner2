import requests

class ThreatIntel:
    def __init__(self):
        self.api_url = "https://api.abuseipdb.com/api/v2/check"
        self.api_key = "YOUR_API_KEY"

    def check_ip(self, ip):
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip}
        response = requests.get(self.api_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "ip": ip,
                "abuseConfidenceScore": data["abuseConfidenceScore"],
                "countryCode": data["countryCode"],
                "domain": data["domain"]
            }
        return {"ip": ip, "error": "Failed to fetch"}
