import requests

class GeoLocator:
    def locate(self, ip):
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            return {"ip": ip, "city": data.get("city"), "country": data.get("country_name")}
        return {"ip": ip, "error": "Location not found"}
