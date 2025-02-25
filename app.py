import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
import tldextract
import random

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

# Footer generation functions and styles
def generate_bubbles(n=20):
    bubbles = []
    for _ in range(n):
        size = 2 + random.random() * 4
        distance = 6 + random.random() * 4
        position = -5 + random.random() * 110
        time = 2 + random.random() * 2
        delay = -1 * (2 + random.random() * 2)
        style = f"--size:{size}rem; --distance:{distance}rem; --position:{position}%; --time:{time}s; --delay:{delay}s;"
        bubbles.append(f'<div class="bubble" style="{style}"></div>')
    return "\n".join(bubbles)

def get_footer_html():
    bubbles_html = generate_bubbles(20)
    footer_content = """
<div class="content">
    <div>
        <div>
            <b>Phishing Detector</b>
            <p>© 2025 - Created By Zouine Mohamed</p>
        </div>
    </div>
    <div>
        <a href="#" target="_blank" title="GitHub"><i class="fa fa-github" style="font-size:24px"></i></a>
        <a href="#" target="_blank" title="LinkedIn"><i class="fa fa-linkedin" style="font-size:24px"></i></a>
    </div>
</div>
    """
    footer_html = f"""
<div class="footer">
    <div class="bubbles">
        {bubbles_html}
    </div>
{footer_content}
</div>
    """
    return footer_html

svg_filter = """
<svg style="position:fixed; top:100vh">
    <defs>
        <filter id="blob">
            <feGaussianBlur in="SourceGraphic" stdDeviation="10" result="blur"></feGaussianBlur>
            <feColorMatrix in="blur" mode="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 19 -9" result="blob"></feColorMatrix>
        </filter>
    </defs>
</svg>
"""

footer_css = """
.footer {
    z-index: 1;
    --footer-background: #0E1117;
    display: grid;
    position: relative;
    min-height: 12rem;
    width: 100%;
}

.footer .bubbles {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1rem;
    background: #49B2E1;
    filter: url("#blob");
}

.footer .bubble {
    position: absolute;
    left: var(--position, 50%);
    background: var(--footer-background);
    border-radius: 100%;
    animation: bubble-size var(--time, 4s) ease-in infinite var(--delay, 0s),
               bubble-move var(--time, 4s) ease-in infinite var(--delay, 0s);
    transform: translate(-50%, 100%);
}

.footer .content {
    z-index: 2;
    display: grid;
    grid-template-columns: 1fr auto;
    grid-gap: 4rem;
    padding: 2rem;
    background: var(--footer-background);
}

.footer .content a, .footer .content p {
    color: #F5F7FA;
    text-decoration: none;
}

.footer .content b {
    color: white;
}

.footer .content p {
    margin: 0;
    font-size: .75rem;
}

.footer .content > div {
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.footer .content > div > div {
    margin: 0.25rem 0;
}

.footer .content > div > div > * {
    margin-right: .5rem;
}

.footer .content .image {
    align-self: center;
    width: 4rem;
    height: 4rem;
    margin: 0.25rem 0;
    background-size: cover;
    background-position: center;
}

@keyframes bubble-size {
    0%, 75% {
        width: var(--size, 4rem);
        height: var(--size, 4rem);
    }
    100% {
        width: 0rem;
        height: 0rem;
    }
}

@keyframes bubble-move {
    0% {
        bottom: -4rem;
    }
    100% {
        bottom: var(--distance, 10rem);
    }
}
"""

def landing_page():
    # Theme Toggle (inchangé)
    st.sidebar.header("🎨 Thème")
    theme_choice = st.sidebar.radio(
        "Choisissez votre thème", 
        ["Clair", "Sombre"], 
        index=0 if st.session_state.theme == 'light' else 1
    )

    # Update theme based on user selection (inchangé)
    new_theme = 'light' if theme_choice == "Clair" else 'dark'
    if new_theme != st.session_state.theme:
        st.session_state.theme = new_theme
        st.query_params.update(theme=new_theme)
        st.rerun()

    # Header (inchangé)
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
    
    # Include Font Awesome CSS (inchangé)
    st.markdown("""
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    """, unsafe_allow_html=True)

    # Initialisation des états dans st.session_state
    if 'current_url' not in st.session_state:
        st.session_state.current_url = ""
    if 'result' not in st.session_state:
        st.session_state.result = None

    # Centrer l'input et placer le bouton à droite
    col1, col2 = st.columns([3, 1])
    with col1:
        url_input = st.text_input(
            "Entrez l'URL à analyser (avec http:// ou https://) :", 
            placeholder="https://www.example.com",
            key="url_input"  # Ajouter une clé unique pour suivre les changements
        )
        # Vérifier si l'URL a changé
        if url_input != st.session_state.current_url:
            st.session_state.current_url = url_input
            st.session_state.result = None  # Réinitialiser le résultat

    with col2:
        st.write("")  # Espace vide pour aligner le bouton
        if st.button("Analyser l'URL"):
            if url_input:
                with st.spinner("Analyse en cours..."):
                    result = predict_url(url_input)
                    st.session_state.result = result
                    st.session_state.current_url = url_input  # Mettre à jour l'URL courante
            else:
                st.warning("⚠️ Veuillez entrer une URL valide.")

    # Styles pour le message de résultat (inchangés)
    st.markdown("""
    <style>
        .result-card {
            font-size: 1.2em;
            font-weight: bold;
            text-align: center;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.2);
            transition: transform 0.5s ease-in-out, opacity 0.5s ease-in-out, box-shadow 0.3s ease-in-out;
            opacity: 0;
            transform: translateY(20px) rotateX(90deg);
            animation: fadeInUp 0.5s ease-in-out forwards;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05));
            backdrop-filter: blur(5px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            width: 60%;
            margin-left: auto;
            margin-right: auto;
        }
        @keyframes fadeInUp {
            to {
                opacity: 1;
                transform: translateY(0) rotateX(0);
            }
        }
        .result-card:hover {
            transform: rotateY(15deg) rotateX(5deg) scale(1.05);
            box-shadow: 0px 10px 20px rgba(0, 0, 0, 0.3);
        }
        .safe {
            background: linear-gradient(135deg, #D4EDDA, #C3E6CB);
            color: #155724;
            border: 2px solid #28a745;
        }
        .phishing {
            background: linear-gradient(135deg, #F8D7DA, #F5C6CB);
            color: #721C24;
            border: 2px solid #dc3545;
        }
        .result-icon {
            font-size: 2em;
            margin-bottom: 10px;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
        .result-text {
            font-size: 1em;
            margin-top: 10px;
            animation: textReveal 1s ease-in-out;
        }
        @keyframes textReveal {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
    """, unsafe_allow_html=True)

    # Afficher le message de résultat uniquement si un résultat existe
    if st.session_state.result:
        result_text = st.session_state.result.lower()
        if "légitime" in result_text or "sûr" in result_text or "valide" in result_text:
            result_class = "safe"
            result_icon = "✅"
        else:
            result_class = "phishing"
            result_icon = "⚠️"
        st.markdown(f"""
            <div class="result-card {result_class}">
                <div class="result-icon">{result_icon}</div>
                <div class="result-text">{st.session_state.result}</div>
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

def main():
    landing_page()
    st.markdown(f"""
    
        <style>
            {footer_css}
        </style>
            {svg_filter}
        {get_footer_html()}
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()