import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Charger les caractéristiques extraites
df = pd.read_csv("dataset_features.csv")

# Séparer les features (X) et les labels (y)
X = df.drop(columns=["label"])  # Supprimer la colonne label pour garder les features
y = df["label"]  # Label (0 = légitime, 1 = phishing)

# Diviser en ensemble d'entraînement (80%) et de test (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Normalisation des données
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("✅ Données préparées avec succès !")

# Initialiser le modèle
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Entraîner le modèle sur les données d'entraînement
model.fit(X_train, y_train)

# Prédire sur l'ensemble de test
y_pred = model.predict(X_test)

# Afficher la précision
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Précision du modèle : {accuracy * 100:.2f}%")

# Afficher un rapport détaillé
print("🔍 Rapport de classification :\n", classification_report(y_test, y_pred))

# Sauvegarder le modèle et le scaler
joblib.dump(model, "model.pkl")
print("✅ Modèle sauvegardé sous model.pkl")

joblib.dump(scaler, "scaler.pkl")
print("✅ Scaler sauvegardé sous scaler.pkl")

# Sauvegarder l'ordre des features
feature_names = list(X.columns)
joblib.dump(feature_names, "feature_names.pkl")
print("✅ Liste des features sauvegardée sous feature_names.pkl")
