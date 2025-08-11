import folium

class MapVisualizer:
    def __init__(self):
        self.map = folium.Map(location=[0, 0], zoom_start=2)

    def add_marker(self, ip_info):
        if "city" in ip_info and "country" in ip_info:
            folium.Marker(
                location=[ip_info.get("latitude", 0), ip_info.get("longitude", 0)],
                popup=f"{ip_info['ip']} - {ip_info['city']}, {ip_info['country']}"
            ).add_to(self.map)

    def save(self, filename="map.html"):
        self.map.save(filename)
