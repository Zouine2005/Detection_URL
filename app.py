import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
import tldextract

# Determine initial theme from query parameters
def get_initial_theme():
    theme = st.query_params.get("theme", "dark")
    return theme

# Set page configuration as the first Streamlit command
st.set_page_config(page_title="Détecteur de Phishing", page_icon="🛡️", layout="wide")

# Initialize theme in session state
if 'theme' not in st.session_state:
    st.session_state.theme = get_initial_theme()

def get_theme_css(theme):
    if theme == 'dark':
        return """
        :root {
            --bg-primary: #121212;
            --text-primary: #e0e0e0;
            --bg-secondary: #1e1e1e;
            --accent-primary: #4fc3f7;
            --accent-secondary: #03a9f4;
            --text-header: #4fc3f7;
            --gradient-start: #2c3e50;
            --gradient-end: #4fc3f7;
            --card-shadow: rgba(255,255,255,0.1);
        }
        """
    else:
        return """
        :root {
            --bg-primary: #f0f2f6;
            --text-primary: #333;
            --bg-secondary: #ffffff;
            --accent-primary: #3498db;
            --accent-secondary: #2980b9;
            --text-header: #2c3e50;
            --gradient-start: #3498db;
            --gradient-end: #2c3e50;
            --card-shadow: rgba(0,0,0,0.1);
        }
        """

# Comprehensive CSS with theme variables
st.markdown(f"""
<style>
{get_theme_css(st.session_state.theme)}

body {{
    background-color: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Arial', sans-serif;
    transition: all 0.3s ease;
}}

.main {{
    background-color: var(--bg-primary);
}}

.stTitle {{
    color: var(--text-header);
    text-align: center;
    font-weight: bold;
}}

.stHeader {{
    color: var(--accent-primary);
    border-bottom: 2px solid var(--accent-primary);
    padding-bottom: 10px;
}}

.stButton>button {{
    background-color: var(--accent-primary);
    color: white;
    border: none;
    border-radius: 20px;
    padding: 8px 20px;
    transition: all 0.3s ease;
    margin-top: 10px;
}}

.stButton>button:hover {{
    background-color: var(--accent-secondary);
    transform: scale(1.05);
}}

.stTextInput>div>div>input {{
    border-radius: 10px;
    border: 1px solid var(--accent-primary);
    background-color: var(--bg-secondary);
    color: var(--text-primary);
    width: 100%;
}}

.card {{
    background-color: var(--bg-secondary);
    border-radius: 15px;
    padding: 20px;
    box-shadow: 0 4px 6px var(--card-shadow);
    margin-bottom: 20px;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}}

.card:hover {{
    transform: translateY(-5px);
    box-shadow: 0 8px 12px var(--card-shadow);
}}

.card-title {{
    font-size: 1.5em;
    font-weight: bold;
    color: var(--accent-primary);
    margin-bottom: 10px;
}}

.card-content {{
    font-size: 1.4em;
    color: var(--text-primary);
}}

.footer {{
    text-align: center;
    padding: 15px;
    margin-top: 30px;
    color: var(--text-primary);
}}

.social-icons {{
    display: flex;
    justify-content: center;
    gap: 15px;
    margin-top: 10px;
}}

.social-icons a {{
    color: var(--text-primary);
    font-size: 1.5em;
    transition: color 0.3s ease;
}}

.social-icons a:hover {{
    color: var(--accent-primary);
}}
</style>
""", unsafe_allow_html=True)

# Charger le modèle et le scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")  
feature_names = joblib.load("feature_names.pkl")

# Charger la liste des domaines légitimes
df_legitimate = pd.read_csv("legitimate_urls.csv")
legitimate_domains = set(df_legitimate["Domain"])

def extract_features(url):
    """ Fonction pour extraire les caractéristiques d'une URL """
    features = {}
    
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    if domain in legitimate_domains:
        print(f"✅ {url} est reconnu comme un site légitime ! 👍")
        return None
    
    features["url_length"] = len(url)  
    features["has_ip"] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}', url) else 0
    features["num_dots"] = url.count('.')
    features["num_hyphens"] = url.count('-')
    features["num_slashes"] = url.count('/')

    phishing_words = ["secure", "account", "update", "verify", "banking", "free", "login", "password", "paypal", "alert"]
    features["contains_suspicious_word"] = 1 if any(word in url.lower() for word in phishing_words) else 0

    return pd.DataFrame([features])

# Initialisation des compteurs dans st.session_state
if 'total_urls_analyzed' not in st.session_state:
    st.session_state.total_urls_analyzed = 0

if 'phishing_urls_detected' not in st.session_state:
    st.session_state.phishing_urls_detected = 0

def predict_url(url):
    """ Fonction qui prédit si l'URL est phishing ou non """
    if not (url.startswith("http://") or url.startswith("https://")):
        return "❌ Veuillez entrer une URL avec http:// ou https://"
    
    features = extract_features(url)
    
    if features is None:
        st.session_state.total_urls_analyzed += 1
        return "✅ Ce site est légitime ! 👍"

    features = features[feature_names]
    features_scaled = scaler.transform(features)
    prediction = model.predict(features_scaled)[0]

    st.session_state.total_urls_analyzed += 1

    if prediction == 1:
        st.session_state.phishing_urls_detected += 1
        return "⚠️ Site suspect ! (Phishing 🚨)"
    else:
        return "✅ Site sûr ! 👍"


def landing_page():
    # Theme Toggle
    st.sidebar.header("🎨 Thème")
    theme_choice = st.sidebar.radio(
        "Choisissez votre thème", 
        ["Clair", "Sombre"], 
        index=0 if st.session_state.theme == 'light' else 1
    )

    # Update theme based on user selection
    new_theme = 'light' if theme_choice == "Clair" else 'dark'
    if new_theme != st.session_state.theme:
        st.session_state.theme = new_theme
        st.query_params.update(theme=new_theme)
        st.rerun()

    # Header with dynamic gradient background
    st.markdown(f"""
    <div style='background: linear-gradient(135deg, var(--gradient-start), var(--gradient-end)); 
                padding: 30px; 
                border-radius: 15px; 
                color: white; 
                text-align: center;
                margin-bottom: 20px;'>
        <h1>🛡️ Détecteur de Phishing</h1>
        <p>Votre bouclier contre les menaces en ligne</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Centrer l'input et placer le bouton à droite
    col1, col2 = st.columns([3, 1])
    with col1:
        url_input = st.text_input("Entrez l'URL à analyser (avec http:// ou https://) :", 
                                  placeholder="https://www.example.com")
    with col2:
        st.write("")  # Espace vide pour aligner le bouton
        if st.button("Analyser l'URL"):
            if url_input:
                with st.spinner("Analyse en cours..."):
                    result = predict_url(url_input)
                    # Stocker le résultat dans session_state pour l'afficher plus bas
                    st.session_state.result = result
            else:
                st.warning("⚠️ Veuillez entrer une URL valide.")
     
    # Afficher le résultat en dessous de l'input
    st.markdown("""
    <style>
        .result-card {
            font-size: 1.5em;
            font-weight: bold;
            text-align: center;
            padding: 15px;
            border-radius: 12px;
            margin-top: 20px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.2);
            transition: transform 0.3s ease-in-out;
        }
        
        .result-card:hover {
            transform: scale(1.05);
        }

        .safe {
            background-color: #D4EDDA;
            color: #155724;
            border: 2px solid #28a745;
        }

        .phishing {
            background-color: #F8D7DA;
            color: #721C24;
            border: 2px solid #dc3545;
        }
    </style>
    """, unsafe_allow_html=True)

    # Afficher le message de résultat sous l'input, centré et stylisé
    if 'result' in st.session_state:
        result_text = st.session_state.result.lower()  # Convertir en minuscules pour éviter les erreurs
        if "légitime" in result_text or "sûr" in result_text or "valide" in result_text:
            result_class = "safe"
        else:
            result_class = "phishing"
    
        st.markdown(f"""
            <div class="result-card {result_class}">
                {st.session_state.result}
            </div>
        """, unsafe_allow_html=True)
    
    # Afficher les résultats d'analyse sous forme de trois cards
    svg_icon = """
<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="#4AB2E1" class="bi bi-diagram-3-fill" viewBox="0 0 16 16">
    <path fill-rule="evenodd" d="M6 3.5A1.5 1.5 0 0 1 7.5 2h1A1.5 1.5 0 0 1 10 3.5v1A1.5 1.5 0 0 1 8.5 6v1H14a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-1 0V8h-5v.5a.5.5 0 0 1-1 0V8h-5v.5a.5.5 0 0 1-1 0v-1A.5.5 0 0 1 2 7h5.5V6A1.5 1.5 0 0 1 6 4.5zm-6 8A1.5 1.5 0 0 1 1.5 10h1A1.5 1.5 0 0 1 4 11.5v1A1.5 1.5 0 0 1 2.5 14h-1A1.5 1.5 0 0 1 0 12.5zm6 0A1.5 1.5 0 0 1 7.5 10h1a1.5 1.5 0 0 1 1.5 1.5v1A1.5 1.5 0 0 1 8.5 14h-1A1.5 1.5 0 0 1 6 12.5zm6 0a1.5 1.5 0 0 1 1.5-1.5h1a1.5 1.5 0 0 1 1.5 1.5v1a1.5 1.5 0 0 1-1.5 1.5h-1a1.5 1.5 0 0 1-1.5-1.5z"/>
</svg>
"""
    st.markdown(f"""
    <div style="display: flex; align-items: center; gap: 10px;">
        {svg_icon} .
        <h2 style="margin: 0;">Statistiques</h2>
    </div>
    """, unsafe_allow_html=True)


    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="card">
            <div class="card-title">URLs Analysées</div>
            <div class="card-content">
                <p style="font-size: 2em; text-align: center;">{st.session_state.total_urls_analyzed}</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Sites Suspects</div>
            <div class="card-content">
                <p style="font-size: 2em; text-align: center;">{st.session_state.phishing_urls_detected}</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        detection_rate = (st.session_state.phishing_urls_detected / st.session_state.total_urls_analyzed) * 100 if st.session_state.total_urls_analyzed > 0 else 0
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Taux de Détection</div>
            <div class="card-content">
                <p style="font-size: 2em; text-align: center;">{detection_rate:.2f}%</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Information Section
        svg_icon = """
<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="#4AB2E1"  class="bi bi-lightning-charge-fill" viewBox="0 0 16 16">
  <path d="M11.251.068a.5.5 0 0 1 .227.58L9.677 6.5H13a.5.5 0 0 1 .364.843l-8 8.5a.5.5 0 0 1-.842-.49L6.323 9.5H3a.5.5 0 0 1-.364-.843l8-8.5a.5.5 0 0 1 .615-.09z"/>
</svg>
"""
    st.markdown(f"""
    <div style="display: flex; align-items: center; gap: 10px;">
        {svg_icon} .
        <h2 style="margin: 0;">Comment ça marche ?</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Créer une grille de cards pour chaque étape du processus
    col1, col2 = st.columns(2)  # Deux colonnes pour organiser les cards
    
    with col1:
        # Card 1 : Analyse approfondie
        st.markdown(f"""
        <div class="card">
            <div class="card-title">🕵️ Analyse approfondie</div>
            <div class="card-content">
                Nous examinons en détail les caractéristiques de l'URL, telles que sa longueur, sa structure et son contenu.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Card 2 : Détection des signes de phishing
        st.markdown(f"""
        <div class="card">
            <div class="card-title">🚨 Détection des signes de phishing</div>
            <div class="card-content">
                Nous recherchons des motifs suspects, comme des mots-clés associés au phishing ou des adresses IP masquées.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Card 3 : Vérification des sites légitimes
        st.markdown(f"""
        <div class="card">
            <div class="card-title">✅ Vérification des sites légitimes</div>
            <div class="card-content">
                Nous comparons l'URL à une base de données de sites de confiance pour vérifier son authenticité.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Card 4 : Protection en temps réel
        st.markdown(f"""
        <div class="card">
            <div class="card-title">🔒 Protection en temps réel</div>
            <div class="card-content">
                Nous offrons une protection immédiate contre les menaces en ligne grâce à une analyse en temps réel.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Footer avec les icônes de réseaux sociaux
    st.markdown("---")
    st.markdown(f"""
    <div class="footer">
        <p>© 2025 Détecteur de Phishing. Tous droits réservés.</p>
        <div class="social-icons">
            <a href="https://twitter.com" target="_blank">𝕏</a>
            <a href="https://linkedin.com" target="_blank">🔗</a>
            <a href="https://github.com" target="_blank">🐙</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Affichage de la page d'accueil
def main():
    landing_page()

if __name__ == "__main__":
    main()