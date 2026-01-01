#!/usr/bin/env python3
"""
Script de test simple pour vérifier les bases du projet
Usage: python test_all.py
"""

import sys
import os

def test_basic_imports():
    """Test des imports de base"""
    print("[TEST] Test des imports de base...")

    try:
        import flask
        import flask_sqlalchemy
        import pandas
        import numpy
        import nltk
        import matplotlib
        import requests
        import bs4  # beautifulsoup4
        import schedule
        import smtplib
        import fpdf2
        import sklearn

        print("[OK] Toutes les dependances sont installees")
        return True
    except ImportError as e:
        print(f"[ERREUR] Dependance manquante: {e}")
        return False

def test_project_imports():
    """Test des imports du projet"""
    print("\n[TEST] Test des modules du projet...")

    try:
        import database
        import analyze
        import charts
        import automation
        import email_alerts

        # Tester que les classes existent
        db_class = database.db
        analyzer_class = analyze.VulnerabilityAnalyzer
        charts_class = charts.VulnerabilityCharts
        automation_instance = automation.automation_system
        email_class = email_alerts.EmailAlertSystem

        print("[OK] Tous les modules du projet importent")
        return True
    except ImportError as e:
        print(f"[ERREUR] Module manquant: {e}")
        return False
    except AttributeError as e:
        print(f"[ERREUR] Attribut manquant: {e}")
        return False

def test_data_generation():
    """Test de génération des données"""
    print("\n[TEST] Test de generation des donnees...")

    try:
        # Simplement vérifier que le script existe et peut être importé
        import add_test_data
        print("[OK] Script de donnees de test disponible")
        return True
    except Exception as e:
        print(f"[ERREUR] Probleme avec le script de donnees: {e}")
        return False

def run_basic_tests():
    """Exécuter les tests de base"""
    print("=== TESTS DE BASE DU PROJET VTDBA ===")
    print("=" * 50)

    tests = [
        ("Imports de base", test_basic_imports),
        ("Modules du projet", test_project_imports),
        ("Generation donnees", test_data_generation),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[ERREUR] Exception dans {test_name}: {e}")
            failed += 1

    print("\n" + "=" * 50)
    print("=== RESULTATS ===")
    print(f"[OK] Tests reussis: {passed}")
    print(f"[ERREUR] Tests echoues: {failed}")
    print(f"Taux de reussite: {(passed/(passed+failed)*100):.1f}%")

    if failed == 0:
        print("\n[SUCCESS] Tests de base reussis !")
        print("Vous pouvez maintenant lancer l'application.")
        return True
    else:
        print(f"\n[WARNING] {failed} test(s) ont echoue.")
        print("Installez les dependances manquantes.")
        return False

def show_instructions():
    """Afficher les instructions"""
    print("\n" + "=" * 60)
    print("GUIDE DE LANCEMENT DE L'APPLICATION")
    print("=" * 60)

    print("""
POUR LANCER L'APPLICATION:

1. Preparer l'environnement:
   python -m pip install -r requirements.txt

2. Generer les donnees de test:
   python add_test_data.py

3. Lancer l'application:
   python app.py

4. Acceder a l'application:
   Ouvrez votre navigateur et allez sur:
   http://127.0.0.1:5000

FONCTIONNALITES DISPONIBLES:
- Accueil (/): Statistiques generales
- Recherche (/search): Filtrage des vulnerabilites
- Rapports (/reports): Graphiques et analyses
- Admin (/admin): Controle de l'automatisation
- PDF (/generate_pdf): Generation de rapports

CONFIGURATION OPTIONNELLE:
- Pour les emails: creer un fichier .env
- Pour l'automatisation: ENABLE_AUTOMATION=true python app.py
""")

if __name__ == "__main__":
    success = run_basic_tests()
    show_instructions()

    if success:
        print("\n*** LANCEMENT RECOMMANDE ***")
        print("python app.py")
    else:
        print("\n*** CORRIGEZ LES ERREURS AVANT DE LANCER ***")
        sys.exit(1)