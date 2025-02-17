import requests
import pandas as pd

# 1-Nouvelle source d'URLs de phishing
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

def download_phishing_urls():
    response = requests.get(URLHAUS_URL)
    if response.status_code == 200:
        with open("phishing_urls.csv", "wb") as file:
            file.write(response.content)
        print("✅ Fichier phishing_urls.csv téléchargé avec succès !")
    else:
        print(f"❌ Erreur {response.status_code} lors du téléchargement des données.")

# Télécharger les URLs de phishing
download_phishing_urls()

# Télécharger les URLs de phishing
download_phishing_urls()

# 2-Charger les URLs légitimes 
LEGITIMATE_URL = "https://downloads.majestic.com/majestic_million.csv"

def download_legitimate_urls():
    response = requests.get(LEGITIMATE_URL)
    if response.status_code == 200:
        with open("legitimate_urls.csv", "wb") as file:
            file.write(response.content)
        print("✅ Fichier legitimate_urls.csv téléchargé avec succès !")
    else:
        print(f"❌ Erreur {response.status_code} lors du téléchargement des données.")

# Télécharger les URLs légitimes
download_legitimate_urls()

# 3-Charger les URLs de phishing
df_phishing = pd.read_csv("phishing_urls.csv", skiprows=9, usecols=[2], names=["url"])
df_phishing["label"] = 1  # Phishing

# Charger les URLs légitimes
df_legit = pd.read_csv("legitimate_urls.csv", usecols=[2], names=["url"])
df_legit["label"] = 0  # Légitime

# Fusionner les deux datasets
df = pd.concat([df_phishing, df_legit], ignore_index=True)

# Sauvegarder le dataset final
df.to_csv("dataset_urls.csv", index=False)

print("✅ Dataset complet enregistré sous dataset_urls.csv !")
