import pandas as pd
import tldextract
import re

# Charger le dataset
df = pd.read_csv("dataset_urls.csv")

# Liste de mots-clés suspects souvent utilisés dans le phishing
suspicious_words = ["login", "verify", "bank", "secure", "account", "update", "free", "password", "signin"]

def extract_features(url):
    # Longueur totale de l'URL
    url_length = len(url)
    
    # Nombre de points dans l'URL
    num_dots = url.count('.')
    
    # Nombre de tirets (-) dans l'URL
    num_hyphens = url.count('-')
    
    # Nombre de barres obliques (/)
    num_slashes = url.count('/')
    
    # Vérifier si l'URL contient une adresse IP
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
    
    # Extraire le domaine
    extracted = tldextract.extract(url)
    domain = extracted.domain
    
    # Vérifier la présence de mots suspects
    contains_suspicious_word = any(word in url.lower() for word in suspicious_words)

    return [url_length, num_dots, num_hyphens, num_slashes, has_ip, contains_suspicious_word]

# Appliquer l'extraction sur toutes les URLs
df_features = df["url"].apply(lambda x: extract_features(str(x)))

# Convertir en DataFrame
columns = ["url_length", "num_dots", "num_hyphens", "num_slashes", "has_ip", "contains_suspicious_word"]
df_features = pd.DataFrame(df_features.tolist(), columns=columns)

# Ajouter les labels
df_features["label"] = df["label"]

# Sauvegarder les features extraites
df_features.to_csv("dataset_features.csv", index=False)

print("✅ Extraction des caractéristiques terminée et enregistrée dans dataset_features.csv !")
