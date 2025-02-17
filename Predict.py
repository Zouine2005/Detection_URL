import joblib
import pandas as pd
import tldextract
import re
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler

# Charger le modèle et le scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")  
feature_names = joblib.load("feature_names.pkl")

# Charger la liste des domaines légitimes
df_legitimate = pd.read_csv("legitimate_urls.csv")  # Remplace par ton vrai fichier
legitimate_domains = set(df_legitimate["Domain"])  # Convertir en ensemble pour une recherche rapide

def extract_features(url):
    """ Fonction pour extraire les caractéristiques d'une URL """
    features = {}
    
    # Extraire le domaine principal (ex: "google" et "com")
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"  # Ex: google.com
    
    # Vérifier si l'URL est dans la liste des sites légitimes
    if domain in legitimate_domains:
        print(f"✅ {url} est reconnu comme un site légitime ! 👍")
        return None  # On ne fait pas d'analyse car c'est un site sûr
    
    # Longueur de l'URL
    features["url_length"] = len(url)  

    # Vérifier si l'URL contient une adresse IP
    features["has_ip"] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}', url) else 0

    # Nombre de points (.) dans l'URL
    features["num_dots"] = url.count('.')

    # Nombre de tirets (-) dans l'URL
    features["num_hyphens"] = url.count('-')

    # Nombre de slashes (/) dans l'URL
    features["num_slashes"] = url.count('/')

    # Vérifier la présence de mots suspects
    phishing_words = ["secure", "account", "update", "verify", "banking", "free", "login", "password", "paypal", "alert"]
    features["contains_suspicious_word"] = 1 if any(word in url.lower() for word in phishing_words) else 0

    return pd.DataFrame([features])

def predict_url(url):
    """ Fonction qui prédit si l'URL est phishing ou non """
    if not (url.startswith("http://") or url.startswith("https://")):
        print("❌ Veuillez entrer une URL avec http:// ou https://")
        return

    # Extraire les caractéristiques de l’URL
    features = extract_features(url)
    
    if features is None:
        return  # L'URL est légitime, pas besoin de prédiction

    # Réorganiser les colonnes dans l'ordre exact utilisé lors de l'entraînement
    features = features[feature_names]

    # Normaliser les données avec le même scaler utilisé lors de l'entraînement
    features_scaled = scaler.transform(features)

    # Faire la prédiction
    prediction = model.predict(features_scaled)[0]

    # Afficher le résultat
    if prediction == 1:
        print(f"⚠️ {url} est POTENTIELLEMENT un site de PHISHING ! 🚨")
    else:
        print(f"✅ {url} est probablement SÛRE ! 👍")

# Interface utilisateur
if __name__ == "__main__":
    url_input = input("🔗 Entrez une URL à analyser (avec http:// ou https://) : ")
    predict_url(url_input)
