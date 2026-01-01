"""
Collecteur OSV + GitHub API
Adapté pour le projet VTBDA
"""

import requests
import time
from datetime import datetime
from .base_collector import BaseCollector


class OSVGitHubCollector(BaseCollector):
    """Collecteur pour OSV (Open Source Vulnerabilities) + GitHub Issues API"""
    
    # Configuration
    PACKAGES = [
        ("npm", "lodash"),
        ("npm", "axios"),
        ("npm", "express"),
        ("npm", "react"),
        ("PyPI", "requests"),
        ("PyPI", "django"),
        ("PyPI", "flask"),
        ("Maven", "spring-boot"),
    ]
    
    GITHUB_KEYWORDS = [
        "docker security vulnerability",
        "kubernetes CVE",
        "jenkins exploit",
        "ci/cd pipeline security",
        "github actions vulnerability"
    ]
    
    OSV_API = "https://api.osv.dev/v1/query"
    GITHUB_API_URL = "https://api.github.com/search/issues"
    
    def __init__(self):
        super().__init__(name="OSV+GitHub")
        self.osv_vulnerabilities = []
        self.github_issues = []
    
    def collect(self):
        """
        Collecte principale : OSV + GitHub
        
        Returns:
            List[Dict]: Liste combinée des vulnérabilités
        """
        # Collecter depuis OSV
        print(f"[{self.name}] Collecte OSV pour {len(self.PACKAGES)} packages...")
        self.osv_vulnerabilities = self._collect_osv()
        
        # Collecter depuis GitHub
        print(f"[{self.name}] Collecte GitHub Issues...")
        self.github_issues = self._collect_github()
        
        # Combiner les résultats
        all_vulns = self.osv_vulnerabilities + self.github_issues
        
        print(f"[{self.name}] Total collecté : {len(all_vulns)} vulnérabilités")
        
        return all_vulns
    
    def _collect_osv(self):
        """
        Collecter les vulnérabilités depuis OSV
        
        Returns:
            List[Dict]: Vulnérabilités OSV normalisées
        """
        vulnerabilities = []
        
        for ecosystem, package in self.PACKAGES:
            try:
                print(f"  → {ecosystem}/{package}...", end=" ")
                
                # Requête OSV API
                payload = {
                    "package": {
                        "ecosystem": ecosystem,
                        "name": package
                    }
                }
                
                response = requests.post(
                    self.OSV_API,
                    json=payload,
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                vulns = data.get("vulns", [])
                
                print(f"{len(vulns)} trouvées")
                
                # Normaliser chaque vulnérabilité
                for vuln in vulns:
                    normalized = self._normalize_osv_vuln(vuln, package, ecosystem)
                    vulnerabilities.append(normalized)
                
                # Pause pour ne pas surcharger l'API
                time.sleep(0.3)
            
            except Exception as e:
                print(f"ERREUR : {e}")
                self.error_count += 1
        
        return vulnerabilities
    
    def _collect_github(self):
        """
        Collecter les issues GitHub liées à la sécurité
        
        Returns:
            List[Dict]: Issues GitHub normalisées
        """
        issues = []
        
        headers = {
            'Accept': 'application/vnd.github.v3+json'
        }
        
        for keyword in self.GITHUB_KEYWORDS:
            try:
                print(f"  → GitHub: '{keyword}'...", end=" ")
                
                params = {
                    'q': f"{keyword} is:issue",
                    'sort': 'created',
                    'order': 'desc',
                    'per_page': 5
                }
                
                response = requests.get(
                    self.GITHUB_API_URL,
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                items = data.get('items', [])
                
                print(f"{len(items)} issues")
                
                # Normaliser chaque issue
                for item in items:
                    normalized = self._normalize_github_issue(item, keyword)
                    issues.append(normalized)
                
                # Pause pour respecter rate limit GitHub
                time.sleep(1)
            
            except Exception as e:
                print(f"ERREUR : {e}")
                self.error_count += 1
        
        return issues
    
    def _normalize_osv_vuln(self, vuln, package, ecosystem):
        """
        Normaliser une vulnérabilité OSV
        
        Args:
            vuln: Vulnérabilité brute OSV
            package: Nom du package
            ecosystem: Écosystème (npm, PyPI, etc.)
        
        Returns:
            Dict: Vulnérabilité normalisée
        """
        vuln_id = vuln.get('id', '')
        summary = vuln.get('summary', '')
        published = vuln.get('published', '')
        
        # Extraire sévérité
        severity_list = vuln.get('severity', [])
        severity = ''
        if severity_list and len(severity_list) > 0:
            severity = severity_list[0].get('type', '')
        
        # Extraire références
        references = []
        for ref in vuln.get('references', []):
            url = ref.get('url')
            if url:
                references.append(url)
        
        # Versions affectées
        affected_versions = []
        for affected in vuln.get('affected', []):
            pkg = affected.get('package', {}).get('name', '')
            ranges = affected.get('ranges', [])
            affected_versions.append(f"{pkg}:{ranges}")
        
        return {
            'source': 'OSV',
            'vuln_id': vuln_id,
            'package': package,
            'ecosystem': ecosystem,
            'severity': severity,
            'summary': summary,
            'affected_versions': ', '.join(affected_versions),
            'references': references,
            'published': published,
            'collected_at': datetime.now().isoformat()
        }
    
    def _normalize_github_issue(self, issue, keyword):
        """
        Normaliser une issue GitHub
        
        Args:
            issue: Issue brute GitHub
            keyword: Mot-clé de recherche
        
        Returns:
            Dict: Issue normalisée
        """
        return {
            'source': 'GitHub Issues',
            'vuln_id': f"GH-{issue.get('number', '')}",
            'package': keyword,
            'ecosystem': 'github',
            'severity': 'MEDIUM',  # Par défaut
            'summary': f"[{keyword}] {issue.get('title', '')}",
            'affected_versions': '',
            'references': [issue.get('html_url', '')],
            'published': issue.get('created_at', ''),
            'collected_at': datetime.now().isoformat()
        }


# Test du collecteur
if __name__ == "__main__":
    print("=" * 70)
    print("TEST DU COLLECTEUR OSV + GITHUB")
    print("=" * 70)
    
    collector = OSVGitHubCollector()
    stats = collector.run()
    
    print("\n✅ Test terminé !")
    print(f"📊 Résultats : {stats}")