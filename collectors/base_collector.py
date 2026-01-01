"""
Classe de base pour tous les collecteurs
Fournit les méthodes communes d'interaction avec la BDD
"""

from abc import ABC, abstractmethod
from database import VulnerabilityDB
from datetime import datetime
import time


class BaseCollector(ABC):
    """Classe abstraite de base pour tous les collecteurs"""

    def __init__(self, name="BaseCollector"):
        self.name = name
        self.db = VulnerabilityDB()
        self.collected_count = 0
        self.inserted_count = 0
        self.duplicate_count = 0
        self.error_count = 0
        self.start_time = None

    @abstractmethod
    def collect(self):
        """
        Méthode principale de collecte
        À implémenter par chaque collecteur

        Returns:
            List[Dict]: Liste des vulnérabilités collectées
        """
        pass

    def _normalize_db_return(self, ret):
        """
        Normaliser différents formats de retour DB.

        Supporte:
          - bool
          - tuple(bool, msg)
          - int (id inséré) / None

        Retour:
          (success: bool, is_duplicate: bool, msg: str)
        """
        # (success, msg)
        if isinstance(ret, tuple) and len(ret) >= 1:
            success = bool(ret[0])
            msg = str(ret[1]) if len(ret) > 1 else ""
            # si pas success => on considère duplicate/skip
            return success, (not success), msg

        # bool
        if isinstance(ret, bool):
            return ret, (not ret), ""

        # id inséré (int) ou autre truthy
        if ret:
            return True, False, ""

        # None / 0 / falsy
        return False, True, ""

    def save_to_database(self, vulnerabilities):
        print(f"[{self.name}] Sauvegarde de {len(vulnerabilities)} vulnérabilités...")

        for vuln in vulnerabilities:
            try:
                # Décider si c'est une CVE générale ou un package
                if vuln.get('ecosystem') and vuln.get('package'):
                    # C'est une vulnérabilité de package
                    package_data = {
                        'package_name': vuln.get('package'),
                        'ecosystem': self._normalize_ecosystem(vuln.get('ecosystem')),
                        'vulnerability_type': self._extract_vuln_type(vuln.get('summary', '')),
                        'cvss_score': self._extract_cvss_score(vuln.get('severity', '')),
                        'severity': self._normalize_severity(vuln.get('severity', '')),
                        'title': vuln.get('summary', 'No title')[:200],
                        'description': vuln.get('summary', 'No description'),
                        'published_date': self._parse_date(vuln.get('published')),
                        'discovered_date': self._parse_date(vuln.get('collected_at')),
                        'affected_versions': (vuln.get('affected_versions', '') or '')[:255],
                        'patched_version': self._extract_patched_version(vuln.get('affected_versions', '')),
                        'source': vuln.get('source', self.name),
                        'url': self._get_first_reference(vuln.get('references', []))
                    }

                    ret = self.db.insert_package_vulnerability(package_data)
                    success, is_duplicate, _ = self._normalize_db_return(ret)

                    if success:
                        self.inserted_count += 1
                    elif is_duplicate:
                        self.duplicate_count += 1
                    else:
                        self.error_count += 1

                else:
                    # C'est une CVE générale
                    cve_data = {
                        'cve_id': vuln.get('vuln_id', ''),
                        'title': vuln.get('summary', 'No title')[:200],
                        'description': vuln.get('summary', 'No description'),
                        'cvss_score': self._extract_cvss_score(vuln.get('severity', '')),
                        'severity': self._normalize_severity(vuln.get('severity', '')),
                        'published_date': self._parse_date(vuln.get('published')),
                        'modified_date': self._parse_date(vuln.get('collected_at')),
                        'url': self._get_first_reference(vuln.get('references', []))
                    }

                    # ⚠️ ICI: insert_cve peut retourner bool OU (bool, msg)
                    ret = self.db.insert_cve(cve_data)
                    success, is_duplicate, _ = self._normalize_db_return(ret)

                    if success:
                        self.inserted_count += 1
                    elif is_duplicate:
                        self.duplicate_count += 1
                    else:
                        self.error_count += 1

            except Exception as e:
                self.error_count += 1
                print(f"[{self.name}] Erreur sauvegarde : {e}")

        return {
            'collected': self.collected_count,
            'inserted': self.inserted_count,
            'duplicates': self.duplicate_count,
            'errors': self.error_count
        }

    def run(self):
        """
        Exécuter le collecteur complet : collecte + sauvegarde

        Returns:
            Dict: Statistiques complètes
        """
        print(f"\n{'='*60}")
        print(f"[{self.name}] Démarrage de la collecte...")
        print(f"{'='*60}")

        self.start_time = time.time()

        # Collecter
        vulnerabilities = self.collect()
        self.collected_count = len(vulnerabilities)

        # Sauvegarder
        stats = self.save_to_database(vulnerabilities)

        # Calculer durée
        duration = time.time() - self.start_time

        # Afficher résumé
        print(f"\n{'='*60}")
        print(f"[{self.name}] Collecte terminée en {duration:.2f}s")
        print(f"  ✓ Collectées  : {stats['collected']}")
        print(f"  ✓ Insérées    : {stats['inserted']}")
        print(f"  ⚠ Doublons    : {stats['duplicates']}")
        print(f"  ✗ Erreurs     : {stats['errors']}")
        print(f"{'='*60}\n")

        return stats

    # ========== MÉTHODES UTILITAIRES ==========

    def _normalize_severity(self, severity):
        """Normaliser la sévérité"""
        if not severity:
            return 'MEDIUM'

        sev = str(severity).upper()

        # Mapping
        if 'CRITICAL' in sev or 'CVSS_V4' in sev:
            return 'CRITICAL'
        elif 'HIGH' in sev or 'CVSS_V3' in sev:
            return 'HIGH'
        elif 'MEDIUM' in sev or 'MODERATE' in sev:
            return 'MEDIUM'
        elif 'LOW' in sev:
            return 'LOW'
        else:
            return 'MEDIUM'

    def _extract_cvss_score(self, severity):
        """Extraire un score CVSS approximatif"""
        sev = self._normalize_severity(severity)

        scores = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }

        return scores.get(sev, 5.0)

    def _parse_date(self, date_str):
        """Parser une date ISO"""
        if not date_str:
            return datetime.now().strftime('%Y-%m-%d')

        try:
            # Format ISO : 2025-12-23T17:09:22.862759
            if 'T' in str(date_str):
                return str(date_str).split('T')[0]
            return str(date_str)[:10]
        except Exception:
            return datetime.now().strftime('%Y-%m-%d')

    def _get_first_reference(self, references):
        """Obtenir la première référence URL"""
        if not references:
            return ''

        if isinstance(references, list) and len(references) > 0:
            return references[0]

        return str(references)[:500]

    def _extract_vuln_type(self, summary):
        """Extraire le type de vulnérabilité depuis le résumé"""
        summary_lower = str(summary).lower()

        if 'denial of service' in summary_lower or 'dos' in summary_lower:
            return 'DoS'
        elif 'injection' in summary_lower:
            return 'Injection'
        elif 'xss' in summary_lower or 'cross-site' in summary_lower:
            return 'XSS'
        elif 'rce' in summary_lower or 'remote code' in summary_lower:
            return 'RCE'
        elif 'prototype pollution' in summary_lower:
            return 'Prototype Pollution'
        elif 'ssrf' in summary_lower:
            return 'SSRF'
        else:
            return 'Other'

    def _extract_patched_version(self, affected_versions):
        """Extraire la version patchée (placeholder)"""
        return ''

    def _normalize_ecosystem(self, ecosystem):
        """
        Normaliser les noms d'écosystèmes pour correspondre au schéma BDD
        """
        if not ecosystem:
            return 'npm'

        ecosystem_map = {
            # Python
            'PyPI': 'pip',
            'pypi': 'pip',
            'Python': 'pip',
            'PYPI': 'pip',

            # Java
            'Maven': 'maven',
            'MAVEN': 'maven',
            'maven': 'maven',

            # JavaScript
            'npm': 'npm',
            'NPM': 'npm',
            'Node': 'npm',
            'node': 'npm',
            'nodejs': 'npm',

            # Docker
            'Docker': 'docker',
            'docker': 'docker',
            'DOCKER': 'docker',

            # Kubernetes
            'Kubernetes': 'kubernetes',
            'kubernetes': 'kubernetes',
            'k8s': 'kubernetes',
            'K8s': 'kubernetes',

            # GitHub
            'GitHub': 'github',
            'github': 'github',
            'Github': 'github',
            'GITHUB': 'github'
        }

        ecosystem_clean = str(ecosystem).strip()
        return ecosystem_map.get(ecosystem_clean, 'npm')
