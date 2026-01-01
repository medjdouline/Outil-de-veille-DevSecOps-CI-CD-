from database import VulnerabilityDB
from datetime import datetime, timedelta
import random

def generate_realistic_descriptions():
    """
    Générer des descriptions réalistes pour différents types de vulnérabilités
    """
    
    descriptions_templates = {
        'RCE': [
            "A critical Remote Code Execution vulnerability allows attackers to execute arbitrary code on the target system. The vulnerability exists in the request parsing mechanism, where unsanitized user input is passed directly to system execution functions. Successful exploitation grants complete control over the affected system, enabling attackers to install malware, modify files, or establish persistent backdoors.",
            "Remote Code Execution flaw in the authentication module permits unauthenticated attackers to execute system commands with elevated privileges. The vulnerability stems from improper input validation in the login handler, allowing injection of shell metacharacters. Exploits have been observed in the wild targeting internet-facing instances.",
            "Critical RCE vulnerability discovered in the template rendering engine. Attackers can inject malicious code through specially crafted template expressions that bypass security filters. The vulnerability affects all versions prior to the security patch and can be exploited remotely without authentication."
        ],
        
        'XSS': [
            "Cross-Site Scripting vulnerability allows injection of malicious JavaScript code into web pages viewed by other users. The flaw exists in the comment processing function where user-supplied data is not properly sanitized before being displayed. Attackers can steal session cookies, redirect users to phishing sites, or perform actions on behalf of victims.",
            "Reflected XSS vulnerability in the search functionality enables attackers to execute arbitrary JavaScript in users' browsers. The vulnerability occurs when search queries are reflected in the response without proper encoding. Exploitation requires tricking users into clicking a malicious link containing the XSS payload.",
            "Stored XSS vulnerability in the profile management feature allows persistent injection of malicious scripts. User-supplied profile data is stored in the database and displayed to other users without sanitization, leading to automatic execution of attacker-controlled JavaScript code."
        ],
        
        'SQL Injection': [
            "SQL Injection vulnerability in the user authentication system allows attackers to bypass login mechanisms and extract sensitive database information. The flaw exists in the username field where input is concatenated directly into SQL queries without parameterization. Successful exploitation can lead to complete database compromise, including access to passwords, personal information, and financial data.",
            "Critical SQL Injection flaw discovered in the reporting module enables unauthorized access to backend databases. Attackers can manipulate query parameters to retrieve, modify, or delete arbitrary data. The vulnerability affects the ORDER BY clause where column names are not properly validated.",
            "Time-based blind SQL Injection vulnerability allows attackers to infer database contents through response timing analysis. While direct data extraction is not possible, attackers can systematically extract information character by character, enabling full database enumeration over time."
        ],
        
        'Supply Chain Attack': [
            "Supply chain compromise detected in popular dependency package. Malicious code was injected into version 2.4.1 through a compromised maintainer account. The backdoor establishes communication with attacker-controlled servers and can exfiltrate environment variables, including API keys and credentials. Over 10,000 projects are estimated to be affected.",
            "Typosquatting attack targeting popular package ecosystem. Malicious package with a similar name to a legitimate library contains code that harvests credentials and cryptocurrency wallet data. The package accumulated over 2,000 downloads before detection and removal.",
            "Dependency confusion vulnerability allows attackers to inject malicious packages into private repositories. By publishing packages with identical names to internal dependencies on public registries, attackers can trick package managers into downloading and executing malicious code during the build process."
        ],
        
        'Path Traversal': [
            "Directory traversal vulnerability in the file download functionality allows attackers to access files outside the intended directory. By using '../' sequences in filename parameters, attackers can read sensitive system files including configuration files, source code, and credentials. The vulnerability affects both Linux and Windows deployments.",
            "Path traversal flaw in the image upload handler permits reading arbitrary files from the server filesystem. Insufficient validation of user-supplied paths combined with improper access controls enables attackers to retrieve sensitive data such as /etc/passwd, application logs, and database configuration files.",
            "Critical path traversal vulnerability in the backup restoration feature allows authenticated users to write files to arbitrary locations on the filesystem. This can be exploited to overwrite critical system files, plant webshells, or escalate privileges by modifying application code."
        ],
        
        'Command Injection': [
            "OS Command Injection vulnerability in the network diagnostics tool allows attackers to execute arbitrary system commands. User input from the 'ping' and 'traceroute' features is passed unsanitized to shell execution functions. Successful exploitation grants command-line access with the privileges of the web server process.",
            "Command injection flaw in the video processing pipeline permits execution of malicious commands through crafted filename inputs. Attackers can exploit this to execute system commands, establish reverse shells, or perform lateral movement within the network.",
            "Critical command injection vulnerability in the email handling subsystem. Specially crafted email headers containing shell metacharacters can break out of the intended command context and execute arbitrary code on the mail server."
        ],
        
        'Prototype Pollution': [
            "Prototype pollution vulnerability in the object merging utility allows attackers to inject properties into Object.prototype, affecting all JavaScript objects in the application. This can lead to authentication bypass, privilege escalation, or remote code execution depending on how the polluted properties are used downstream.",
            "Critical prototype pollution flaw in the configuration parser enables attackers to modify application behavior by polluting global object properties. Exploitation can result in security control bypass, denial of service, or arbitrary code execution in Node.js environments.",
            "Prototype pollution vulnerability discovered in the JSON parsing functionality. Attackers can inject malicious properties that propagate to all objects, potentially bypassing security checks, modifying application logic, or triggering remote code execution."
        ],
        
        'Dependency Confusion': [
            "Dependency confusion attack vector identified in the package resolution mechanism. Attackers can publish malicious packages to public repositories with names matching internal private packages. When package managers prioritize public repositories, the malicious code gets installed instead of the legitimate internal dependency.",
            "Supply chain vulnerability through dependency confusion allows attackers to inject malicious code into build pipelines. By exploiting the package manager's name resolution algorithm, attackers can substitute internal packages with attacker-controlled versions containing backdoors or data exfiltration code.",
            "Critical dependency confusion vulnerability in the CI/CD pipeline. Misconfigured package managers fetch dependencies from public registries even when private registry credentials are available, enabling attackers to hijack internal package names and inject malicious code into production builds."
        ]
    }
    
    return descriptions_templates


def generate_comprehensive_test_data():
    """Générer 50+ vulnérabilités avec descriptions complètes"""
    
    descriptions = generate_realistic_descriptions()
    
    components = [
        'Docker', 'Kubernetes', 'Jenkins', 'GitLab CI', 'GitHub Actions',
        'Terraform', 'Ansible', 'Helm', 'Prometheus', 'Grafana',
        'SonarQube', 'OWASP ZAP', 'Burp Suite', 'Wireshark', 'npm',
        'Python pip', 'Maven', 'Gradle', 'webpack', 'lodash'
    ]
    
    ecosystems = ['docker', 'kubernetes', 'npm', 'pip', 'maven', 'github']
    
    vuln_types = list(descriptions.keys())
    
    severity_weights = {
        'CRITICAL': 0.15,
        'HIGH': 0.30,
        'MEDIUM': 0.35,
        'LOW': 0.15,
        'NONE': 0.05
    }
    
    def get_random_severity():
        rand = random.random()
        cumulative = 0
        for severity, weight in severity_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return severity
        return 'MEDIUM'
    
    def get_cvss_for_severity(severity):
        ranges = {
            'CRITICAL': (9.0, 10.0),
            'HIGH': (7.0, 8.9),
            'MEDIUM': (4.0, 6.9),
            'LOW': (0.1, 3.9),
            'NONE': (0.0, 0.0)
        }
        min_val, max_val = ranges.get(severity, (4.0, 6.9))
        return round(random.uniform(min_val, max_val), 1)
    
    vulnerabilities = []
    
    # Générer 50 vulnérabilités
    for i in range(50):
        year = random.choice([2023, 2024, 2025])
        number = random.randint(1000, 9999)
        cve_id = f'CVE-{year}-{number:04d}'
        
        severity = get_random_severity()
        cvss_score = get_cvss_for_severity(severity)
        component = random.choice(components)
        ecosystem = random.choice(ecosystems)
        vuln_type = random.choice(vuln_types)
        
        # Choisir une description aléatoire pour ce type de vulnérabilité
        description = random.choice(descriptions[vuln_type])
        
        days_ago = random.randint(1, 90)
        published_date = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d')
        modified_date = (datetime.now() - timedelta(days=days_ago-5)).strftime('%Y-%m-%d')
        
        title = f'{vuln_type} vulnerability in {component}'
        
        sources = ['NVD', 'GitHub Security', 'MITRE', 'Vendor Advisory', 'CISA KEV']
        source = random.choice(sources)
        
        if source == 'NVD':
            url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        elif source == 'GitHub Security':
            gh_id = f'GHSA-{"".join(random.choices("abcd", k=4))}-{"".join(random.choices("abcd", k=4))}-{"".join(random.choices("abcd", k=4))}'
            url = f'https://github.com/advisories/{gh_id}'
        else:
            url = f'https://example.com/advisory/{cve_id}'
        
        vuln_data = {
            'cve_id': cve_id,
            'title': title,
            'description': description,
            'severity': severity,
            'cvss_score': cvss_score,
            'component': component,
            'ecosystem': ecosystem,
            'vulnerability_type': vuln_type,
            'published_date': published_date,
            'modified_date': modified_date,
            'source': source,
            'url': url,
            'affected_versions': f'< {random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
            'patched_version': f'{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
        }
        
        vulnerabilities.append(vuln_data)
    
    return vulnerabilities


def add_test_data():
    """Ajouter les données de test dans SQLite"""
    
    db = VulnerabilityDB()
    
    # Vérifier si des données existent déjà
    stats = db.get_total_count()
    if stats['total'] > 0:
        print(f"⚠️ {stats['total']} vulnérabilités existent déjà !")
        response = input("Voulez-vous ajouter plus de données de test ? (o/N): ")
        if response.lower() not in ['o', 'oui', 'yes', 'y']:
            return
    
    print("📄 Génération des données de test avec descriptions complètes...")
    
    # Générer les vulnérabilités
    vulnerabilities = generate_comprehensive_test_data()
    
    # Insérer dans la base de données
    for vuln in vulnerabilities:
        # Décider si c'est une CVE ou un package (50/50)
        if random.random() > 0.5:
            # CVE générale
            cve_data = {
                'cve_id': vuln['cve_id'],
                'title': vuln['title'],
                'description': vuln['description'],
                'cvss_score': vuln['cvss_score'],
                'severity': vuln['severity'],
                'published_date': vuln['published_date'],
                'modified_date': vuln['modified_date'],
                'url': vuln['url']
            }
            db.insert_cve(cve_data)
        else:
            # Package vulnérabilité
            package_data = {
                'package_name': vuln['component'],
                'ecosystem': vuln['ecosystem'],
                'vulnerability_type': vuln['vulnerability_type'],
                'cvss_score': vuln['cvss_score'],
                'severity': vuln['severity'],
                'title': vuln['title'],
                'description': vuln['description'],
                'published_date': vuln['published_date'],
                'discovered_date': vuln['published_date'],
                'affected_versions': vuln['affected_versions'],
                'patched_version': vuln['patched_version'],
                'source': vuln['source'],
                'url': vuln['url']
            }
            db.insert_package_vulnerability(package_data)
    
    # Ajouter quelques articles
    articles = [
        {
            'title': 'Docker Security Best Practices 2024',
            'content': 'Comprehensive guide to securing Docker containers including image scanning, runtime protection, and network policies...',
            'source': 'Docker Blog',
            'category': 'docker',
            'url': 'https://docker.com/blog/security-2024',
            'published_date': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        },
        {
            'title': 'Supply Chain Attacks in npm Ecosystem',
            'content': 'Analysis of recent supply chain attacks targeting npm packages, including dependency confusion and typosquatting...',
            'source': 'Snyk Blog',
            'category': 'supply-chain',
            'url': 'https://snyk.io/blog/npm-attacks',
            'published_date': (datetime.now() - timedelta(days=14)).strftime('%Y-%m-%d')
        },
        {
            'title': 'Kubernetes Security Hardening Guide',
            'content': 'Step-by-step guide to hardening Kubernetes clusters including RBAC, network policies, and pod security standards...',
            'source': 'Kubernetes Blog',
            'category': 'kubernetes',
            'url': 'https://kubernetes.io/blog/security-hardening',
            'published_date': (datetime.now() - timedelta(days=21)).strftime('%Y-%m-%d')
        }
    ]
    
    for article in articles:
        db.insert_article(article)
    
    # Ajouter des tendances
    trends = [
        ('docker', 15, 'HIGH'),
        ('kubernetes', 12, 'MEDIUM'),
        ('supply-chain', 8, 'CRITICAL'),
        ('rce', 6, 'CRITICAL'),
        ('npm', 10, 'HIGH'),
        ('jenkins', 5, 'MEDIUM')
    ]
    
    for keyword, count, severity in trends:
        db.insert_trend(keyword, count, severity)
    
    # Ajouter des relations supply-chain
    supply_chain_relations = [
        ('my-app', 'lodash', 'npm'),
        ('web-server', 'express', 'npm'),
        ('k8s-controller', 'kubernetes-client', 'pip'),
        ('ci-pipeline', 'jenkins-plugin', 'maven')
    ]
    
    for parent, dependent, ecosystem in supply_chain_relations:
        db.insert_supply_chain(parent, dependent, ecosystem)
    
    # Afficher les statistiques finales
    final_stats = db.get_total_count()
    severity_stats = db.get_severity_stats()
    
    print("\n✅ Données de test ajoutées avec succès !")
    print("📊 Statistiques:")
    print(f"   • Total: {final_stats['total']} vulnérabilités")
    print(f"   • CVE: {final_stats['cve_count']}")
    print(f"   • Packages: {final_stats['package_count']}")
    
    print("\n📈 Distribution par sévérité:")
    for severity, data in severity_stats.items():
        print(f"   • {severity}: {data['count']} ({data['percentage']}%)")
    
    print("\n✅ Base de données prête à l'emploi !")
    print("🚀 Lancez l'application avec: python app.py")


if __name__ == '__main__':
    add_test_data()