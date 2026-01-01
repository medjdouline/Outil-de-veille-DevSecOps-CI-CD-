from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Vulnerability(db.Model):
    """
    Table principale des vulnérabilités (vue unifiée pour l'app Flask).
    Peut représenter soit une CVE générale, soit une vulnérabilité de package.
    """
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)

    # Identifiants / base
    cve_id = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Niveau de gravité
    severity = db.Column(db.String(20))  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score = db.Column(db.Float)

    # Contexte technique / DevSecOps
    affected_component = db.Column(db.String(100))  # Docker, GitHub Actions, Kubernetes, etc.
    ecosystem = db.Column(db.String(50))            # npm, pip, maven, docker, kubernetes, github
    vulnerability_type = db.Column(db.String(100))  # RCE, injection, prototype pollution, etc.

    # Dates
    discovered_date = db.Column(db.DateTime, default=datetime.utcnow)
    published_date = db.Column(db.DateTime)
    modified_date = db.Column(db.DateTime)

    # Source & lien
    source = db.Column(db.String(100))              # NVD, GitHub Advisory, etc.
    url = db.Column(db.String(500))

    # Infos packages (supply-chain)
    affected_versions = db.Column(db.String(255))
    patched_version = db.Column(db.String(100))

    # Métadonnées
    collected_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Vulnerability {self.cve_id}>"


class Article(db.Model):
    """
    Table pour stocker les articles / rapports collectés
    (blog posts, advisories, rapports techniques, etc.)
    """
    __tablename__ = 'articles'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)
    source = db.Column(db.String(100))
    category = db.Column(db.String(50))  # supply-chain, github-actions, docker, kubernetes, etc.
    url = db.Column(db.String(500))

    published_date = db.Column(db.DateTime)
    collected_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Article {self.title}>"


class Trend(db.Model):
    """
    Table pour l'analyse des tendances (mots-clés / technologies)
    Ex : docker, kubernetes, github, ci/cd, npm, etc.
    """
    __tablename__ = 'trends'

    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(100), nullable=False)  # compromised packages, supply-chain, etc.
    count = db.Column(db.Integer, default=1)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    severity_level = db.Column(db.String(20))  # optionnel : niveau moyen associé au mot-clé

    def __repr__(self):
        return f"<Trend {self.keyword}>"


class PackageRelationship(db.Model):
    """
    Table pour la supply-chain : relations de dépendance entre packages.
    Inspirée de la table 'supply_chain' du script sqlite.
    """
    __tablename__ = 'supply_chain'

    id = db.Column(db.Integer, primary_key=True)

    parent_package = db.Column(db.String(100), nullable=False)     # qui utilise
    dependent_package = db.Column(db.String(100), nullable=False)  # qui est utilisé
    ecosystem = db.Column(db.String(50))                           # npm, pip, maven, docker...

    # Lien optionnel vers une vulnérabilité (package_vulnerability)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'))
    vulnerability = db.relationship('Vulnerability', backref='supply_chain_links')

    impact_score = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<SupplyChain {self.parent_package} -> {self.dependent_package}>"
