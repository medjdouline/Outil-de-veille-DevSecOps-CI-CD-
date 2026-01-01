"""
Script de test pour vérifier que la migration SQLite fonctionne correctement
Usage: python test_migration.py
"""

import sys
import os


def test_imports():
    """Tester que tous les modules s'importent correctement"""
    print("\n[TEST] Verification des imports...")
    
    try:
        from database import VulnerabilityDB
        print("  OK - database.py")
        
        from analyze import VulnerabilityAnalyzer
        print("  OK - analyze.py")
        
        from charts import PDFReportGenerator, VulnerabilityCharts
        print("  OK - charts.py")
        
        from app import app
        print("  OK - app.py")
        
        return True
    except ImportError as e:
        print(f"  ERREUR - {e}")
        return False


def test_database_creation():
    """Tester la création de la base de données"""
    print("\n[TEST] Creation de la base de donnees...")
    
    try:
        from database import VulnerabilityDB
        db = VulnerabilityDB()
        
        # Vérifier que les tables existent
        import sqlite3
        conn = sqlite3.connect('data/vulnerabilities.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = [
            'cve_vulnerabilities',
            'package_vulnerabilities',
            'supply_chain',
            'articles',
            'trends'
        ]
        
        all_exist = all(table in tables for table in required_tables)
        
        if all_exist:
            print(f"  OK - Toutes les tables existent: {', '.join(required_tables)}")
            conn.close()
            return True
        else:
            missing = [t for t in required_tables if t not in tables]
            print(f"  ERREUR - Tables manquantes: {', '.join(missing)}")
            conn.close()
            return False
            
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_insert_operations():
    """Tester les opérations d'insertion"""
    print("\n[TEST] Operations d'insertion...")
    
    try:
        from database import VulnerabilityDB
        db = VulnerabilityDB()
        
        # Test 1: Insérer une CVE
        test_cve = {
            'cve_id': 'CVE-2025-TEST-001',
            'title': 'Test vulnerability',
            'description': 'This is a test vulnerability for migration verification',
            'cvss_score': 7.5,
            'severity': 'HIGH',
            'published_date': '2025-01-01',
            'url': 'https://example.com/CVE-2025-TEST-001'
        }
        
        if db.insert_cve(test_cve):
            print("  OK - Insertion CVE")
        else:
            print("  ERREUR - Insertion CVE echouee")
            return False
        
        # Test 2: Insérer un package
        test_package = {
            'package_name': 'test-package',
            'ecosystem': 'npm',
            'vulnerability_type': 'RCE',
            'cvss_score': 9.0,
            'severity': 'CRITICAL',
            'title': 'Test package vulnerability',
            'description': 'This is a test package vulnerability for migration verification',
            'published_date': '2025-01-01',
            'discovered_date': '2025-01-01',
            'source': 'Test',
            'url': 'https://example.com/test-package'
        }
        
        vuln_id = db.insert_package_vulnerability(test_package)
        if vuln_id:
            print("  OK - Insertion Package")
        else:
            print("  ERREUR - Insertion Package echouee")
            return False
        
        # Test 3: Insérer supply-chain
        if db.insert_supply_chain('parent-pkg', 'test-package', 'npm', vuln_id):
            print("  OK - Insertion Supply-chain")
        else:
            print("  ERREUR - Insertion Supply-chain echouee")
            return False
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_query_operations():
    """Tester les opérations de requête"""
    print("\n[TEST] Operations de requete...")
    
    try:
        from database import VulnerabilityDB
        db = VulnerabilityDB()
        
        # Test 1: Récupérer toutes les CVE
        cve_df = db.get_all_cve()
        print(f"  OK - Recuperation CVE: {len(cve_df)} enregistrements")
        
        # Test 2: Récupérer tous les packages
        pkg_df = db.get_all_packages()
        print(f"  OK - Recuperation Packages: {len(pkg_df)} enregistrements")
        
        # Test 3: Statistiques
        stats = db.get_total_count()
        print(f"  OK - Statistiques: Total={stats['total']}, CVE={stats['cve_count']}, PKG={stats['package_count']}")
        
        # Test 4: Distribution par sévérité
        severity_stats = db.get_severity_stats()
        print(f"  OK - Distribution severite: {len(severity_stats)} niveaux")
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_analyzer_functions():
    """Tester les fonctions d'analyse"""
    print("\n[TEST] Fonctions d'analyse...")
    
    try:
        from analyze import VulnerabilityAnalyzer
        
        # Test 1: Statistiques globales
        stats = VulnerabilityAnalyzer.get_statistics()
        print(f"  OK - Statistiques: {stats['total_vulnerabilities']} vulnerabilites")
        
        # Test 2: Top composants
        top_components = VulnerabilityAnalyzer.get_top_affected_components(limit=5)
        print(f"  OK - Top composants: {len(top_components)} composants")
        
        # Test 3: Distribution sévérité
        severity_dist = VulnerabilityAnalyzer.get_severity_distribution()
        print(f"  OK - Distribution severite: {len(severity_dist)} niveaux")
        
        # Test 4: Filtrage
        results = VulnerabilityAnalyzer.filter_vulnerabilities(severity='HIGH')
        print(f"  OK - Filtrage: {len(results)} resultats HIGH")
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_chart_generation():
    """Tester la génération de graphiques"""
    print("\n[TEST] Generation de graphiques...")
    
    try:
        from charts import VulnerabilityCharts
        
        # Test 1: Graphique sévérité
        chart_path = VulnerabilityCharts.create_severity_pie_chart('test_severity.png')
        if chart_path and os.path.exists(chart_path):
            print("  OK - Graphique severite")
            os.remove(chart_path)
        else:
            print("  ERREUR - Graphique severite non cree")
            return False
        
        # Test 2: Graphique tendances
        chart_path = VulnerabilityCharts.create_trends_bar_chart('test_trends.png')
        if chart_path:
            if os.path.exists(chart_path):
                print("  OK - Graphique tendances")
                os.remove(chart_path)
            else:
                print("  INFO - Graphique tendances non cree (pas de donnees)")
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_pdf_generation():
    """Tester la génération de PDF"""
    print("\n[TEST] Generation PDF...")
    
    try:
        from charts import PDFReportGenerator
        
        generator = PDFReportGenerator()
        pdf_path = generator.generate_report('test_rapport.pdf')
        
        if os.path.exists(pdf_path):
            print(f"  OK - PDF genere: {pdf_path}")
            os.remove(pdf_path)
            return True
        else:
            print("  ERREUR - PDF non genere")
            return False
            
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_flask_app():
    """Tester l'application Flask"""
    print("\n[TEST] Application Flask...")
    
    try:
        from app import app
        
        # Créer un client de test
        client = app.test_client()
        
        # Test 1: Page d'accueil
        response = client.get('/')
        if response.status_code == 200:
            print("  OK - Page d'accueil (200)")
        else:
            print(f"  ERREUR - Page d'accueil ({response.status_code})")
            return False
        
        # Test 2: Page de recherche
        response = client.get('/search')
        if response.status_code == 200:
            print("  OK - Page de recherche (200)")
        else:
            print(f"  ERREUR - Page de recherche ({response.status_code})")
            return False
        
        # Test 3: Page de rapports
        response = client.get('/reports')
        if response.status_code == 200:
            print("  OK - Page de rapports (200)")
        else:
            print(f"  ERREUR - Page de rapports ({response.status_code})")
            return False
        
        # Test 4: API statistiques
        response = client.get('/api/statistics')
        if response.status_code == 200:
            print("  OK - API statistiques (200)")
        else:
            print(f"  ERREUR - API statistiques ({response.status_code})")
            return False
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def test_descriptions():
    """Vérifier que toutes les vulnérabilités ont des descriptions"""
    print("\n[TEST] Verification des descriptions...")
    
    try:
        from database import VulnerabilityDB
        db = VulnerabilityDB()
        
        # Vérifier CVE
        cve_df = db.get_all_cve()
        if len(cve_df) > 0:
            missing_desc_cve = cve_df[cve_df['description'].isna() | (cve_df['description'] == '')].shape[0]
            if missing_desc_cve == 0:
                print(f"  OK - Toutes les CVE ({len(cve_df)}) ont des descriptions")
            else:
                print(f"  AVERTISSEMENT - {missing_desc_cve} CVE sans description")
        
        # Vérifier Packages
        pkg_df = db.get_all_packages()
        if len(pkg_df) > 0:
            missing_desc_pkg = pkg_df[pkg_df['description'].isna() | (pkg_df['description'] == '')].shape[0]
            if missing_desc_pkg == 0:
                print(f"  OK - Tous les packages ({len(pkg_df)}) ont des descriptions")
            else:
                print(f"  AVERTISSEMENT - {missing_desc_pkg} packages sans description")
        
        return True
        
    except Exception as e:
        print(f"  ERREUR - {e}")
        return False


def run_all_tests():
    """Exécuter tous les tests"""
    print("=" * 70)
    print("TESTS DE VERIFICATION DE LA MIGRATION SQLITE")
    print("=" * 70)
    
    tests = [
        ("Imports", test_imports),
        ("Creation BDD", test_database_creation),
        ("Insertions", test_insert_operations),
        ("Requetes", test_query_operations),
        ("Analyseur", test_analyzer_functions),
        ("Graphiques", test_chart_generation),
        ("PDF", test_pdf_generation),
        ("Flask App", test_flask_app),
        ("Descriptions", test_descriptions),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[ERREUR CRITIQUE] {test_name}: {e}")
            results.append((test_name, False))
    
    # Résumé
    print("\n" + "=" * 70)
    print("RESULTATS DES TESTS")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    failed = len(results) - passed
    
    for test_name, result in results:
        status = "OK" if result else "ERREUR"
        symbol = "✓" if result else "✗"
        print(f"  {symbol} {test_name}: {status}")
    
    print(f"\nTotal: {passed}/{len(results)} tests reussis")
    
    if failed == 0:
        print("\nTOUS LES TESTS REUSSIS!")
        print("La migration SQLite est fonctionnelle.")
        print("\nProchaines etapes:")
        print("1. Lancer l'application: python app.py")
        print("2. Acceder a: http://127.0.0.1:5000")
        return True
    else:
        print(f"\n{failed} TEST(S) ECHOUE(S)")
        print("Verifiez les erreurs ci-dessus.")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)