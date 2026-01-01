from database import db, Vulnerability, Article, Trend
from sqlalchemy import func
from datetime import datetime, timedelta
from collections import Counter
import pandas as pd
import numpy as np
import re
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.probability import FreqDist
import matplotlib.pyplot as plt
import io
import base64
from sklearn.feature_extraction.text import TfidfVectorizer


class VulnerabilityAnalyzer:
    """Classe pour analyser les vulnérabilités"""

    @staticmethod
    def get_statistics():
        """Retourner les statistiques globales simples"""
        total_vulns = Vulnerability.query.count()
        critical_count = Vulnerability.query.filter_by(severity='CRITICAL').count()
        high_count = Vulnerability.query.filter_by(severity='HIGH').count()

        return {
            'total_vulnerabilities': total_vulns,
            'critical': critical_count,
            'high': high_count,
        }

    @staticmethod
    def get_trends(days=30):
        """Analyser les tendances des 30 derniers jours par composant"""
        date_limit = datetime.utcnow() - timedelta(days=days)
        recent_vulns = Vulnerability.query.filter(
            Vulnerability.discovered_date >= date_limit
        ).all()

        components = [v.affected_component for v in recent_vulns if v.affected_component]
        component_counts = Counter(components)

        return dict(component_counts)

    @staticmethod
    def get_top_affected_components(limit=5):
        """Top N composants les plus affectés"""
        components = db.session.query(
            Vulnerability.affected_component,
            func.count(Vulnerability.id).label('count')
        ).group_by(
            Vulnerability.affected_component
        ).order_by(
            func.count(Vulnerability.id).desc()
        ).limit(limit).all()

        return [
            {'component': c[0], 'count': c[1]}
            for c in components
            if c[0]
        ]

    @staticmethod
    def filter_vulnerabilities(severity=None, component=None, days=None):
        """Filtrer les vulnérabilités selon les critères"""
        query = Vulnerability.query

        if severity:
            query = query.filter_by(severity=severity)

        if component:
            query = query.filter_by(affected_component=component)

        if days:
            date_limit = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Vulnerability.discovered_date >= date_limit)

        return query.all()

    @staticmethod
    def get_vulnerabilities_by_severity():
        """Compte les vulnérabilités par niveau de sévérité (brut)"""
        results = db.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.id).label('count')
        ).group_by(
            Vulnerability.severity
        ).all()

        return {item[0]: item[1] for item in results}

    # ======= NOUVELLES MÉTHODES INSPIRÉES DE L'AUTRE ANALYZER =======

    @staticmethod
    def get_severity_distribution():
        """
        Distribution par sévérité avec pourcentages.
        Exemple de retour :
        {
          'CRITICAL': {'count': 5, 'percentage': 12.5},
          'HIGH': {'count': 10, 'percentage': 25.0},
          ...
        }
        """
        results = db.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).group_by(
            Vulnerability.severity
        ).all()

        total = sum(count for _, count in results)
        distribution = {}

        for severity, count in results:
            percentage = (count / total * 100) if total else 0
            distribution[severity] = {
                'count': count,
                'percentage': round(percentage, 1)
            }

        return distribution

    @staticmethod
    def get_critical_vulnerabilities(limit=10):
        """Vulnérabilités critiques (CVSS >= 9.0), triées par score et date"""
        query = Vulnerability.query.filter(
            Vulnerability.cvss_score >= 9.0
        ).order_by(
            Vulnerability.cvss_score.desc(),
            Vulnerability.published_date.desc()
        )

        vulns = query.limit(limit).all()

        return [
            {
                'id': v.id,
                'cve_id': v.cve_id,
                'title': v.title,
                'cvss_score': v.cvss_score,
                'published_date': v.published_date,
                'url': v.url,
            }
            for v in vulns
        ]

    @staticmethod
    def get_recent_devsecops_trends(days=30):
        """
        Tendances DevSecOps (mots-clés techniques) dans les titres/descriptions
        des vulnérabilités récentes.
        Retourne un Counter (ou dict) avec les mots-clés et leur nombre.
        """
        date_limit = datetime.utcnow() - timedelta(days=days)
        recent = Vulnerability.query.filter(
            Vulnerability.published_date >= date_limit
        ).all()

        keywords = []
        tech_keywords = [
            'docker', 'kubernetes', 'k8s', 'jenkins', 'gitlab', 'github',
            'ci/cd', 'pipeline', 'container', 'terraform',
            'ansible', 'helm', 'npm', 'python', 'maven', 'dependency'
        ]

        for v in recent:
            title = (v.title or '').lower()
            desc = (v.description or '').lower()
            text = f"{title} {desc}"
            for kw in tech_keywords:
                if kw in text:
                    keywords.append(kw)

        return Counter(keywords)

    # ===== NOUVELLES MÉTHODES AVANCÉES AVEC PANDAS/NUMPY/NLTK =====

    @staticmethod
    def download_nltk_data():
        """Télécharger les données NLTK nécessaires"""
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt')

        try:
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('stopwords')

    @staticmethod
    def get_vulnerabilities_dataframe(days=None):
        """Retourner un DataFrame Pandas avec les vulnérabilités"""
        query = Vulnerability.query

        if days:
            date_limit = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Vulnerability.discovered_date >= date_limit)

        vulns = query.all()

        data = []
        for v in vulns:
            data.append({
                'id': v.id,
                'cve_id': v.cve_id,
                'title': v.title,
                'description': v.description or '',
                'severity': v.severity,
                'cvss_score': v.cvss_score,
                'affected_component': v.affected_component,
                'ecosystem': v.ecosystem,
                'vulnerability_type': v.vulnerability_type,
                'published_date': v.published_date,
                'discovered_date': v.discovered_date,
                'source': v.source,
                'url': v.url
            })

        return pd.DataFrame(data)

    @staticmethod
    def analyze_trends_with_pandas(days=90):
        """Analyser les tendances avec Pandas"""
        df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe(days=days)

        if df.empty:
            return {
                'monthly_trends': {},
                'severity_evolution': {},
                'top_components': {},
                'correlation_matrix': {}
            }

        # Tendances mensuelles
        df['published_date'] = pd.to_datetime(df['published_date'])
        df['month'] = df['published_date'].dt.to_period('M')
        monthly_trends = df.groupby('month').size().to_dict()

        # Évolution par sévérité
        severity_evolution = df.groupby(['month', 'severity']).size().unstack(fill_value=0).to_dict()

        # Top composants
        top_components = df['affected_component'].value_counts().head(10).to_dict()

        # Matrice de corrélation (si assez de données numériques)
        numeric_cols = ['cvss_score']
        if len(df) > 5:
            correlation_matrix = df[numeric_cols].corr().to_dict()
        else:
            correlation_matrix = {}

        return {
            'monthly_trends': dict(monthly_trends),
            'severity_evolution': {str(k): v for k, v in severity_evolution.items()},
            'top_components': dict(top_components),
            'correlation_matrix': correlation_matrix
        }

    @staticmethod
    def summarize_text_with_nltk(text, max_sentences=3):
        """Résumer un texte avec NLTK"""
        if not text or len(text.strip()) < 50:
            return text

        VulnerabilityAnalyzer.download_nltk_data()

        try:
            # Tokenization en phrases
            sentences = sent_tokenize(text)

            if len(sentences) <= max_sentences:
                return text

            # Nettoyage et tokenization
            stop_words = set(stopwords.words('english'))
            clean_sentences = []

            for sentence in sentences:
                words = word_tokenize(sentence.lower())
                words = [word for word in words if word.isalnum() and word not in stop_words]
                clean_sentences.append((sentence, words))

            # Score des phrases basé sur la fréquence des mots
            word_freq = FreqDist()
            for _, words in clean_sentences:
                word_freq.update(words)

            sentence_scores = {}
            for i, (sentence, words) in enumerate(clean_sentences):
                score = sum(word_freq[word] for word in words)
                sentence_scores[i] = score

            # Sélection des meilleures phrases
            top_sentences = sorted(sentence_scores.items(), key=lambda x: x[1], reverse=True)[:max_sentences]
            top_sentences = sorted(top_sentences, key=lambda x: x[0])  # Remettre dans l'ordre

            summary = ' '.join([sentences[i] for i, _ in top_sentences])
            return summary

        except Exception as e:
            print(f"Erreur lors du résumé NLTK: {e}")
            return text[:200] + "..." if len(text) > 200 else text

    @staticmethod
    def get_text_vectorization():
        """Créer une vectorisation TF-IDF des descriptions avec NumPy"""
        df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe()

        if df.empty or df['description'].str.len().sum() < 100:
            return {
                'vocabulary_size': 0,
                'top_terms': [],
                'vectors_shape': (0, 0)
            }

        # Nettoyer les textes
        texts = df['description'].fillna('').tolist()
        cleaned_texts = []

        for text in texts:
            # Nettoyage basique
            text = re.sub(r'[^\w\s]', '', text.lower())
            text = re.sub(r'\d+', '', text)
            cleaned_texts.append(text)

        # Vectorisation TF-IDF
        vectorizer = TfidfVectorizer(max_features=100, stop_words='english', ngram_range=(1, 2))
        tfidf_matrix = vectorizer.fit_transform(cleaned_texts)

        # Convertir en array NumPy
        tfidf_array = tfidf_matrix.toarray()

        # Termes les plus fréquents
        feature_names = vectorizer.get_feature_names_out()
        top_terms = []

        if tfidf_array.shape[0] > 0:
            # Calculer la fréquence moyenne des termes
            mean_scores = np.mean(tfidf_array, axis=0)
            top_indices = np.argsort(mean_scores)[-10:][::-1]
            top_terms = [feature_names[i] for i in top_indices]

        return {
            'vocabulary_size': len(feature_names),
            'top_terms': top_terms,
            'vectors_shape': tfidf_array.shape
        }

    @staticmethod
    def generate_matplotlib_charts(days=30):
        """Générer des graphiques avec Matplotlib et les retourner en base64"""
        df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe(days=days)

        if df.empty:
            return {}

        charts = {}

        # 1. Distribution par sévérité
        severity_counts = df['severity'].value_counts()
        plt.figure(figsize=(10, 6))
        severity_counts.plot(kind='bar', color=['red', 'orange', 'blue', 'green'])
        plt.title('Distribution des Vulnérabilités par Sévérité')
        plt.xlabel('Sévérité')
        plt.ylabel('Nombre')
        plt.xticks(rotation=45)

        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        charts['severity_distribution'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        # 2. Évolution temporelle
        if len(df) > 5:
            df['published_date'] = pd.to_datetime(df['published_date'])
            df['date'] = df['published_date'].dt.date
            daily_counts = df.groupby('date').size()

            plt.figure(figsize=(12, 6))
            daily_counts.plot(kind='line', marker='o')
            plt.title('Évolution des Vulnérabilités dans le Temps')
            plt.xlabel('Date')
            plt.ylabel('Nombre de Vulnérabilités')
            plt.xticks(rotation=45)

            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            charts['temporal_evolution'] = base64.b64encode(buffer.getvalue()).decode()
            plt.close()

        # 3. Top composants affectés
        component_counts = df['affected_component'].value_counts().head(10)
        if len(component_counts) > 0:
            plt.figure(figsize=(10, 8))
            component_counts.plot(kind='pie', autopct='%1.1f%%')
            plt.title('Top 10 Composants Affectés')
            plt.ylabel('')

            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            charts['top_components'] = base64.b64encode(buffer.getvalue()).decode()
            plt.close()

        return charts

    @staticmethod
    def get_advanced_analytics():
        """Retourner toutes les analyses avancées"""
        return {
            'pandas_trends': VulnerabilityAnalyzer.analyze_trends_with_pandas(),
            'text_vectorization': VulnerabilityAnalyzer.get_text_vectorization(),
            'charts': VulnerabilityAnalyzer.generate_matplotlib_charts(),
            'summaries': VulnerabilityAnalyzer.generate_descriptions_summary()
        }

    @staticmethod
    def generate_descriptions_summary():
        """Générer des résumés des descriptions longues"""
        vulns = Vulnerability.query.filter(Vulnerability.description.isnot(None)).all()

        summaries = []
        for vuln in vulns:
            if vuln.description and len(vuln.description) > 100:
                summary = VulnerabilityAnalyzer.summarize_text_with_nltk(vuln.description)
                summaries.append({
                    'cve_id': vuln.cve_id,
                    'original_length': len(vuln.description),
                    'summary': summary
                })

        return summaries
