# 🛡️ Network Guard

Zaawansowany skaner bezpieczeństwa sieci z AI, analizą zagrożeń, mapą geolokalizacji i GUI.

## 🔧 Instalacja

1. Zainstaluj zależności:
   pip install -r requirements.txt
2. Uruchom aplikację:
  python main.py


## 📦 Funkcje

- Skanowanie LAN
- Sniffer pakietów z wykrywaniem ARP spoofingu
- Analiza reputacji IP (AbuseIPDB)
- Klasyfikacja zagrożeń przez AI
- Mapa geolokalizacji IP

## 🧠 AI

Model RandomForest klasyfikuje zagrożenia na podstawie cech pakietów. Możesz go trenować w `core/ai.py`.

## 🌍 Mapa

Mapa generowana przez `folium`, zapisywana jako `map.html`.

## 🔐 API

Aby korzystać z AbuseIPDB, dodaj swój klucz API w `core/threat_intel.py`.

## 📂 Struktura

Zobacz folder `network_guard/` dla pełnej struktury projektu.
