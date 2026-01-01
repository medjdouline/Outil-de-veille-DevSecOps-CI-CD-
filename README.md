
# 🔒 Outil de Veille Technologique DevSecOps & CI/CD

Un outil **100% fonctionnel** et automatisé de veille technologique pour surveiller les vulnérabilités dans les environnements DevSecOps et CI/CD. L'application repose sur **Flask**, **SQLite**, **Pandas**, **NumPy**, **NLTK**, **Matplotlib**, **Chart.js**, et inclut l'automatisation complète, les rapports PDF, et les alertes email.

## ✨ Fonctionnalités Complètes

### 🔍 Collecte de Données
- **Scraping automatique** : NVD, GitHub Security, Docker/K8s, blogs techniques
- **Collecteurs spécialisés** par équipe (NVD, GitHub, Docker/K8s)
- **Planification automatique** : Collecte toutes les 4 heures

### 📊 Analyse Avancée
- **Pandas & NumPy** : Analyse statistique des tendances et patterns
- **NLTK** : Résumés automatiques des descriptions longues
- **Vectorisation TF-IDF** : Analyse sémantique des textes
- **Tendances temporelles** : Évolution des vulnérabilités

### 📈 Visualisations
- **Matplotlib** : Graphiques statiques haute qualité
- **Chart.js** : Graphiques interactifs animés
- **Tableaux de bord** : Statistiques en temps réel
- **Rapports PDF** : Génération automatique avec graphiques

### 🚨 Automatisation & Alertes
- **Schedule** : Automatisation des collecteurs
- **Email alerts** : Alertes quotidiennes/hebdomadaires
- **Panel d'administration** : Contrôle complet du système

---

## 📋 Table des Matières
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Administration](#administration)
- [API](#api)
- [Tests](#tests)
- [Architecture](#architecture)

---

## 🚀 Installation

### Prérequis
- Python 3.9+
- Git
- Navigateur web moderne

### Étapes d'Installation

```bash
# 1. Cloner le repository
git clone https://github.com/miryamfd/VTBDA.git
cd VTBDA

# 2. Créer l'environnement virtuel
python -m venv venv

# 3. Activer l'environnement virtuel
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Installer les dépendances
pip install -r requirements.txt

# 5. Initialiser la base de données et ajouter des données de test
python add_test_data.py

# 6. Lancer l'application
python app.py
```

### ✅ Vérification de l'Installation

L'application sera accessible sur : **http://127.0.0.1:5000**

---

## ⚙️ Configuration

### Variables d'Environnement (.env)

Créer un fichier `.env` à la racine du projet :

```env
# Configuration Email (pour les alertes)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=votre-email@gmail.com
SENDER_PASSWORD=votre-mot-de-passe-application
RECIPIENT_EMAILS=admin@entreprise.com,securite@entreprise.com

# Automatisation
ENABLE_AUTOMATION=true
```

### Configuration Gmail

1. Activer la vérification en 2 étapes
2. Générer un mot de passe d'application : https://myaccount.google.com/apppasswords
3. Utiliser ce mot de passe (pas votre mot de passe normal) dans `SENDER_PASSWORD`

---

## 🎯 Utilisation

### Interface Web

#### 🏠 Page d'Accueil (`/`)
- **Statistiques globales** : Total vulnérabilités, critiques, haute sévérité
- **Composants les plus affectés** : Top 5 composants vulnérables
- **Navigation rapide** vers recherche et rapports

#### 🔍 Recherche (`/search`)
- **Filtres avancés** :
  - Sévérité (Critical, High, Medium, Low)
  - Composant (Docker, Kubernetes, etc.)
  - Période (X derniers jours)
- **Résultats paginés** avec détails complets

#### 📊 Rapports (`/reports`)
- **Graphiques interactifs** (Chart.js) :
  - Distribution par sévérité (camembert animé)
  - Évolution temporelle (courbe)
  - Top composants (barres)
  - Analyse par écosystème (radar)
- **Graphiques détaillés** (Matplotlib) : Version haute qualité
- **Analyse avancée** :
  - Statistiques Pandas
  - Résumés NLTK automatiques
  - Vectorisation TF-IDF

#### ⚙️ Administration (`/admin`)
- **Contrôle de l'automatisation** : Démarrer/arrêter les collecteurs
- **Actions manuelles** : Lancer la collecte, tester les emails
- **Statistiques temps réel** : État de la base de données
- **Logs système** : Suivi des opérations

---

## 🔧 Administration

### Automatisation

L'automatisation peut être contrôlée via l'interface web ou les variables d'environnement :

```bash
# Activer l'automatisation au démarrage
ENABLE_AUTOMATION=true python app.py
```

### Calendrier Automatique

- **Collecte des données** : Toutes les 4 heures
- **Alertes quotidiennes** : 9h00 (vulnérabilités critiques)
- **Rapport hebdomadaire** : Lundi 8h00 (PDF par email)

### Tests Manuels

Via l'interface admin ou API :

```bash
# Tester la collecte
curl http://localhost:5000/automation/run-collectors

# Tester les emails
curl http://localhost:5000/automation/test-alerts

# Générer un PDF
curl http://localhost:5000/generate_pdf
```

---

## 🔌 API

### Endpoints Disponibles

#### Données
- `GET /api/vulnerabilities` : Liste paginée des vulnérabilités
- `GET /api/statistics` : Statistiques globales JSON

#### Automatisation
- `GET /automation/start` : Démarrer l'automatisation
- `GET /automation/stop` : Arrêter l'automatisation
- `GET /automation/status` : Statut de l'automatisation
- `GET /automation/run-collectors` : Lancer collecte manuelle
- `GET /automation/test-alerts` : Tester les emails

#### Rapports
- `GET /generate_pdf` : Télécharger rapport PDF

### Exemple d'utilisation API

```python
import requests

# Récupérer les statistiques
stats = requests.get('http://localhost:5000/api/statistics').json()
print(f"Total vulnérabilités: {stats['total_vulnerabilities']}")

# Générer un rapport PDF
response = requests.get('http://localhost:5000/generate_pdf')
with open('rapport.pdf', 'wb') as f:
    f.write(response.content)
```

---

## 🧪 Tests

### Script de Test Complet

```bash
# 1. Installation et données de test
python add_test_data.py

# 2. Lancement de l'application
python app.py

# 3. Tests fonctionnels (dans un autre terminal)
```

### Tests Automatisés

```python
# Tests des fonctionnalités principales
from app import app
from analyze import VulnerabilityAnalyzer

with app.app_context():
    # Test des analyses
    stats = VulnerabilityAnalyzer.get_statistics()
    print("✅ Statistiques:", stats)

    # Test des graphiques
    charts = VulnerabilityAnalyzer.generate_matplotlib_charts()
    print("✅ Graphiques générés:", list(charts.keys()))

    # Test des résumés
    summaries = VulnerabilityAnalyzer.generate_descriptions_summary()
    print(f"✅ {len(summaries)} résumés générés")
```

### Tests d'Intégration

1. **Interface Web** :
   - Accéder à toutes les pages
   - Tester les formulaires de recherche
   - Vérifier les graphiques

2. **Base de Données** :
   - Vérifier l'intégrité des données
   - Tester les relations entre tables

3. **Automatisation** :
   - Démarrer/arrêter via l'admin
   - Vérifier les logs
   - Tester les emails

4. **Rapports PDF** :
   - Générer un rapport
   - Vérifier le contenu et les graphiques

---

## 🏗️ Architecture

### Structure des Fichiers

```
VTBDA/
├── app.py                 # Application Flask principale
├── database.py            # Modèles SQLAlchemy
├── analyze.py             # Analyses avancées (Pandas/NLTK)
├── charts.py              # Génération graphiques (Matplotlib/PDF)
├── automation.py          # Système d'automatisation
├── email_alerts.py        # Système d'alertes email
├── add_test_data.py       # Script données de test
├── config.py              # Configuration
├── requirements.txt       # Dépendances Python
├── .env                   # Variables d'environnement
├── data/
│   └── vulnerabilities.db # Base SQLite
├── templates/             # Templates HTML
│   ├── base.html
│   ├── index.html
│   ├── search.html
│   ├── reports.html
│   └── admin.html
├── static/                # Assets statiques
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
└── scrapers/              # Collecteurs
    └── nvd_scraper.py
```

### Technologies Utilisées

| Composant | Technologie | Usage |
|-----------|-------------|-------|
| **Backend** | Flask | Framework web |
| **Base de données** | SQLite + SQLAlchemy | Persistance |
| **Analyse** | Pandas, NumPy | Traitement données |
| **NLP** | NLTK | Résumés textes |
| **Visualisation** | Matplotlib, Chart.js | Graphiques |
| **PDF** | FPDF2 | Rapports |
| **Email** | smtplib | Alertes |
| **Automatisation** | schedule | Tâches planifiées |
| **Web Scraping** | BeautifulSoup, requests | Collecte |

---

## 🎯 Résultats Finaux

Le projet respecte complètement les exigences :

### ✅ Dataset (Table) avec Failles Classées
- **50+ vulnérabilités** de test avec classification complète
- **Champs normalisés** : CVE, sévérité, CVSS, composants, écosystèmes
- **Base SQLite relationnelle** avec contraintes d'intégrité

### ✅ Analyse : Tendances, Dates, Sévérité, Impact
- **Tendances temporelles** : Évolution sur 90 jours
- **Analyse par sévérité** : Distribution et pourcentages
- **Composants affectés** : Top vulnérables
- **Analyse sémantique** : Vectorisation TF-IDF

### ✅ Rapport + Slides avec Graphiques et Conclusions
- **Rapports PDF automatiques** : 5-10 pages avec graphiques
- **Graphiques Matplotlib** : Haute qualité pour publications
- **Graphiques Chart.js** : Interactifs pour l'interface web
- **Tableaux détaillés** : Données exportables

### ✅ Interface Web Complète
- **Responsive design** : Fonctionne sur mobile/desktop
- **Navigation intuitive** : Accueil → Recherche → Rapports → Admin
- **Filtres avancés** : Recherche multicritères
- **Panel d'administration** : Contrôle total du système

### ✅ Automatisation Complète
- **Collecteurs automatiques** : Toutes les 4 heures
- **Alertes email** : Quotidiennes/hebdomadaires
- **Rapports planifiés** : Génération automatique
- **Logs système** : Traçabilité complète

---

**🎉 Le projet est maintenant 100% fonctionnel et prêt pour la démonstration !**

