import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
import tldextract

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
        return "❌ Veuillez entrer une URL avec http:// ou https://"
    
    # Extraire les caractéristiques de l’URL
    features = extract_features(url)
    
    if features is None:
        return "✅ Ce site est légitime ! 👍"  # Pas besoin de prédiction

    # Réorganiser les colonnes dans l'ordre exact utilisé lors de l'entraînement
    features = features[feature_names]

    # Normaliser les données avec le même scaler utilisé lors de l'entraînement
    features_scaled = scaler.transform(features)

    # Faire la prédiction
    prediction = model.predict(features_scaled)[0]

    # Retourner le résultat
    if prediction == 1:
        return "⚠️ Site suspect ! (Phishing 🚨)"
    else:
        return "✅ Site sûr ! 👍"

# Landing Page
def landing_page():
    st.set_page_config(page_title="Détecteur de Phishing", page_icon="🛡️", layout="centered")
    
    # Header
    st.title("🛡️ Détecteur de Phishing")
    st.markdown("Protégez-vous contre les sites de phishing. Entrez une URL pour savoir si elle est sûre ou suspecte.")
    
    # Section d'analyse
    st.header("🔍 Analyse d'URL")
    url_input = st.text_input("Entrez l'URL à analyser (avec http:// ou https://) :", placeholder="https://www.example.com")
    
    if st.button("Analyser l'URL"):
        if url_input:
            with st.spinner("Analyse en cours..."):
                result = predict_url(url_input)
                if "suspect" in result:
                    st.error(result)
                else:
                    st.success(result)
        else:
            st.warning("⚠️ Veuillez entrer une URL valide.")
    
    # Section d'information
    st.header("ℹ️ Informations")
    st.markdown("""
    **Comment ça marche ?**
    - Notre outil analyse l'URL que vous avez entrée et vérifie plusieurs caractéristiques pour détecter les signes de phishing.
    - Si l'URL est reconnue comme légitime, vous verrez un message de confirmation.
    - Si l'URL est suspecte, vous serez averti immédiatement.
    """)

    # Section Développeur
    st.header("👨‍💻 Développeur")
    st.markdown("""
    **Nom :** Zouine Mohamed  
    **Description :**  
    Je suis un développeur passionné par la cybersécurité et la création d'outils pour protéger les utilisateurs contre les menaces en ligne.  
    Ce projet a été créé pour aider les utilisateurs à identifier les sites de phishing et à naviguer en toute sécurité sur Internet.
    """)
    
    # Footer
    st.markdown("---")
    st.markdown("© 2025 Détecteur de Phishing. Tous droits réservés.")

# Affichage de la page d'accueil
if __name__ == "__main__":
    landing_page()