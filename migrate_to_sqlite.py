"""
Script de migration pour convertir les anciennes données Flask-SQLAlchemy vers SQLite pur
Usage: python migrate_to_sqlite.py
"""

import os
import sys
import sqlite3
from datetime import datetime


def check_old_database():
    """Vérifier si l'ancienne base de données existe"""
    old_db_path = 'data/vulnerabilities.db'
    
    if not os.path.exists(old_db_path):
        print("Aucune base de donnees a migrer trouvee.")
        return False
    
    return True


def backup_database():
    """Créer une sauvegarde de l'ancienne base"""
    old_db = 'data/vulnerabilities.db'
    backup_db = f'data/vulnerabilities_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    
    try:
        import shutil
        shutil.copy2(old_db, backup_db)
        print(f"Sauvegarde creee: {backup_db}")
        return True
    except Exception as e:
        print(f"Erreur lors de la sauvegarde: {e}")
        return False


def analyze_old_structure():
    """Analyser la structure de l'ancienne base"""
    conn = sqlite3.connect('data/vulnerabilities.db')
    cursor = conn.cursor()
    
    # Lister les tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    print("\nTables trouvees dans l'ancienne base:")
    for table in tables:
        table_name = table[0]
        print(f"\n  {table_name}:")
        
        # Compter les enregistrements
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"    Nombre d'enregistrements: {count}")
        
        # Lister les colonnes
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        print("    Colonnes:")
        for col in columns:
            print(f"      - {col[1]} ({col[2]})")
    
    conn.close()
    return tables


def migrate_vulnerabilities_table():
    """Migrer la table des vulnérabilités"""
    print("\nMigration de la table 'vulnerabilities'...")
    
    conn = sqlite3.connect('data/vulnerabilities.db')
    cursor = conn.cursor()
    
    try:
        # Vérifier si la table existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
        if not cursor.fetchone():
            print("Table 'vulnerabilities' non trouvee, passage a l'etape suivante.")
            return
        
        # Vérifier les colonnes existantes
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = {col[1]: col[2] for col in cursor.fetchall()}
        
        print(f"Colonnes trouvees: {list(columns.keys())}")
        
        # Ajouter les colonnes manquantes si nécessaire
        if 'title' not in columns:
            print("Ajout de la colonne 'title'...")
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN title TEXT")
        
        if 'description' not in columns:
            print("Ajout de la colonne 'description'...")
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN description TEXT")
        
        # Mettre à jour les enregistrements sans titre/description
        print("Mise a jour des enregistrements...")
        
        cursor.execute("""
            UPDATE vulnerabilities 
            SET title = COALESCE(title, 'Vulnerability in ' || affected_component)
            WHERE title IS NULL OR title = ''
        """)
        
        cursor.execute("""
            UPDATE vulnerabilities 
            SET description = COALESCE(
                description, 
                'Vulnerability of type ' || vulnerability_type || ' affecting ' || affected_component
            )
            WHERE description IS NULL OR description = ''
        """)
        
        conn.commit()
        print("Table 'vulnerabilities' migree avec succes!")
        
    except Exception as e:
        print(f"Erreur lors de la migration: {e}")
        conn.rollback()
    finally:
        conn.close()


def split_vulnerabilities_to_new_structure():
    """
    Diviser la table 'vulnerabilities' en deux tables distinctes:
    - cve_vulnerabilities (CVE générales)
    - package_vulnerabilities (packages DevSecOps)
    """
    print("\nDivision des vulnerabilites en CVE et Packages...")
    
    conn = sqlite3.connect('data/vulnerabilities.db')
    cursor = conn.cursor()
    
    try:
        # Vérifier si les nouvelles tables existent
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_vulnerabilities'")
        if not cursor.fetchone():
            print("Creation de la table 'cve_vulnerabilities'...")
            cursor.execute('''
            CREATE TABLE cve_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                cvss_score REAL,
                severity TEXT,
                published_date TEXT,
                modified_date TEXT,
                source TEXT DEFAULT 'NVD',
                url TEXT,
                collected_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='package_vulnerabilities'")
        if not cursor.fetchone():
            print("Creation de la table 'package_vulnerabilities'...")
            cursor.execute('''
            CREATE TABLE package_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT,
                vulnerability_type TEXT,
                cvss_score REAL,
                severity TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                published_date TEXT,
                discovered_date TEXT,
                affected_versions TEXT,
                patched_version TEXT,
                source TEXT,
                url TEXT,
                collected_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        
        # Migrer les données de l'ancienne table vers les nouvelles
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
        if cursor.fetchone():
            print("Migration des donnees existantes...")
            
            # Récupérer toutes les vulnérabilités
            cursor.execute("SELECT * FROM vulnerabilities")
            old_vulns = cursor.fetchall()
            
            # Récupérer les noms de colonnes
            cursor.execute("PRAGMA table_info(vulnerabilities)")
            columns = [col[1] for col in cursor.fetchall()]
            
            migrated_cve = 0
            migrated_pkg = 0
            
            for row in old_vulns:
                data = dict(zip(columns, row))
                
                # Décider si c'est une CVE ou un package
                if data.get('cve_id') and data['cve_id'].startswith('CVE-'):
                    # C'est une CVE
                    cursor.execute('''
                    INSERT OR IGNORE INTO cve_vulnerabilities 
                    (cve_id, title, description, cvss_score, severity, published_date, url)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('cve_id'),
                        data.get('title', 'No title'),
                        data.get('description', 'No description available'),
                        data.get('cvss_score'),
                        data.get('severity'),
                        data.get('published_date'),
                        data.get('url')
                    ))
                    migrated_cve += 1
                else:
                    # C'est un package
                    cursor.execute('''
                    INSERT INTO package_vulnerabilities 
                    (package_name, ecosystem, vulnerability_type, cvss_score, severity, 
                     title, description, published_date, discovered_date, url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('affected_component', 'Unknown'),
                        data.get('ecosystem'),
                        data.get('vulnerability_type'),
                        data.get('cvss_score'),
                        data.get('severity'),
                        data.get('title', 'No title'),
                        data.get('description', 'No description available'),
                        data.get('published_date'),
                        data.get('discovered_date'),
                        data.get('url')
                    ))
                    migrated_pkg += 1
            
            conn.commit()
            print(f"Migration terminee: {migrated_cve} CVE, {migrated_pkg} packages")
        
    except Exception as e:
        print(f"Erreur lors de la division: {e}")
        conn.rollback()
    finally:
        conn.close()


def verify_migration():
    """Vérifier que la migration s'est bien passée"""
    print("\nVerification de la migration...")
    
    conn = sqlite3.connect('data/vulnerabilities.db')
    cursor = conn.cursor()
    
    # Compter les enregistrements dans chaque table
    cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities")
    cve_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM package_vulnerabilities")
    pkg_count = cursor.fetchone()[0]
    
    print(f"CVE migrees: {cve_count}")
    print(f"Packages migres: {pkg_count}")
    print(f"Total: {cve_count + pkg_count}")
    
    # Vérifier les descriptions
    cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities WHERE description IS NULL OR description = ''")
    missing_desc_cve = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM package_vulnerabilities WHERE description IS NULL OR description = ''")
    missing_desc_pkg = cursor.fetchone()[0]
    
    if missing_desc_cve > 0 or missing_desc_pkg > 0:
        print(f"\nATTENTION: {missing_desc_cve + missing_desc_pkg} enregistrements sans description!")
    else:
        print("\nToutes les vulnerabilites ont des descriptions!")
    
    conn.close()


def main():
    """Fonction principale de migration"""
    print("=" * 60)
    print("SCRIPT DE MIGRATION SQLITE")
    print("=" * 60)
    
    if not check_old_database():
        print("\nAucune migration necessaire.")
        print("La base de donnees sera creee lors du premier lancement de l'application.")
        return
    
    print("\nCe script va migrer votre base de donnees vers la nouvelle structure.")
    response = input("Continuer ? (o/N): ")
    
    if response.lower() not in ['o', 'oui', 'yes', 'y']:
        print("Migration annulee.")
        return
    
    # Étape 1: Sauvegarde
    if not backup_database():
        print("Erreur lors de la sauvegarde. Migration annulee.")
        return
    
    # Étape 2: Analyser la structure
    analyze_old_structure()
    
    # Étape 3: Migrer la table principale
    migrate_vulnerabilities_table()
    
    # Étape 4: Diviser en CVE et Packages
    split_vulnerabilities_to_new_structure()
    
    # Étape 5: Vérifier
    verify_migration()
    
    print("\n" + "=" * 60)
    print("MIGRATION TERMINEE!")
    print("=" * 60)
    print("\nVous pouvez maintenant lancer l'application avec: python app.py")


if __name__ == '__main__':
    main()