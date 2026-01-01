from database import VulnerabilityDB
from datetime import datetime, timedelta
from collections import Counter
import pandas as pd
import numpy as np
import re
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.probability import FreqDist
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import io
import base64
from sklearn.feature_extraction.text import TfidfVectorizer


class VulnerabilityAnalyzer:
    """Classe pour analyser les vulnérabilités avec SQLite"""
    
    def __init__(self):
        self.db = VulnerabilityDB()
    
    @staticmethod
    def get_statistics():
        """Retourner les statistiques globales simples"""
        db = VulnerabilityDB()
        stats = db.get_total_count()
        severity_stats = db.get_severity_stats()
        
        return {
            'total_vulnerabilities': stats['total'],
            'critical': severity_stats.get('CRITICAL', {}).get('count', 0),
            'high': severity_stats.get('HIGH', {}).get('count', 0),
        }
    
    @staticmethod
    def get_trends(days=30):
        """Analyser les tendances des derniers jours par composant"""
        db = VulnerabilityDB()
        trends = db.get_trends(days=days)
        return trends
    
    @staticmethod
    def get_top_affected_components(limit=5):
        """Top N composants les plus affectés"""
        db = VulnerabilityDB()
        components = db.get_top_components(limit=limit)
        return components
    
    @staticmethod
    def filter_vulnerabilities(severity=None, component=None, days=None):
        """Filtrer les vulnérabilités selon les critères"""
        db = VulnerabilityDB()
        df = db.search_vulnerabilities(severity=severity, component=component, days=days)
        
        # Convertir DataFrame en liste de dictionnaires pour compatibilité avec templates
        results = []
        for _, row in df.iterrows():
            results.append({
                'cve_id': row['cve_id'],
                'title': row['title'],
                'description': row['description'],
                'severity': row['severity'],
                'cvss_score': row['cvss_score'],
                'affected_component': row['affected_component'],
                'url': row['url']
            })
        
        return results
    
    @staticmethod
    def get_vulnerabilities_by_severity():
        """Compte les vulnérabilités par niveau de sévérité"""
        db = VulnerabilityDB()
        return db.get_severity_stats()
    
    @staticmethod
    def get_severity_distribution():
        """Distribution par sévérité avec pourcentages"""
        db = VulnerabilityDB()
        return db.get_severity_stats()
    
    @staticmethod
    def get_critical_vulnerabilities(limit=10):
        """Vulnérabilités critiques (CVSS >= 9.0)"""
        db = VulnerabilityDB()
        return db.get_critical_vulnerabilities(limit=limit)
    
    @staticmethod
    def get_recent_devsecops_trends(days=30):
        """Tendances DevSecOps dans les titres/descriptions"""
        db = VulnerabilityDB()
        df = db.get_all_vulnerabilities_combined()
        
        # Filtrer par date
        df['published_date'] = pd.to_datetime(df['published_date'])
        date_limit = datetime.utcnow() - timedelta(days=days)
        recent = df[df['published_date'] >= date_limit]
        
        keywords = []
        tech_keywords = [
            'docker', 'kubernetes', 'k8s', 'jenkins', 'gitlab', 'github',
            'ci/cd', 'pipeline', 'container', 'terraform',
            'ansible', 'helm', 'npm', 'python', 'maven', 'dependency'
        ]
        
        for _, row in recent.iterrows():
            title = str(row['title']).lower() if row['title'] else ''
            desc = str(row['description']).lower() if row['description'] else ''
            text = f"{title} {desc}"
            for kw in tech_keywords:
                if kw in text:
                    keywords.append(kw)
        
        return Counter(keywords)
    
    @staticmethod
    def download_nltk_data():
        """Télécharger les données NLTK nécessaires"""
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt', quiet=True)
        
        try:
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('stopwords', quiet=True)
    
    @staticmethod
    def get_vulnerabilities_dataframe(days=None):
        """Retourner un DataFrame Pandas avec les vulnérabilités"""
        db = VulnerabilityDB()
        df = db.get_all_vulnerabilities_combined()
        
        if days:
            df['published_date'] = pd.to_datetime(df['published_date'])
            date_limit = datetime.utcnow() - timedelta(days=days)
            df = df[df['published_date'] >= date_limit]
        
        return df
    
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
        
        # Evolution par sévérité
        severity_evolution = df.groupby(['month', 'severity']).size().unstack(fill_value=0).to_dict()
        
        # Top composants
        top_components_series = df[df['affected_component'].notna()]['affected_component'].value_counts().head(10)
        top_components = top_components_series.to_dict()
        
        # Matrice de corrélation
        numeric_cols = ['cvss_score']
        if len(df) > 5 and 'cvss_score' in df.columns:
            df_numeric = df[numeric_cols].dropna()
            if len(df_numeric) > 0:
                correlation_matrix = df_numeric.corr().to_dict()
            else:
                correlation_matrix = {}
        else:
            correlation_matrix = {}
        
        return {
            'monthly_trends': {str(k): v for k, v in monthly_trends.items()},
            'severity_evolution': {str(k): v for k, v in severity_evolution.items()},
            'top_components': top_components,
            'correlation_matrix': correlation_matrix
        }
    
    @staticmethod
    def summarize_text_with_nltk(text, max_sentences=3):
        """Résumer un texte avec NLTK"""
        if not text or len(str(text).strip()) < 50:
            return text
        
        return text[:200] + "..." if len(text) > 200 else text
        VulnerabilityAnalyzer.download_nltk_data()
        
        try:
            # Tokenization en phrases
            sentences = sent_tokenize(str(text))
            
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
            top_sentences = sorted(top_sentences, key=lambda x: x[0])
            
            summary = ' '.join([sentences[i] for i, _ in top_sentences])
            return summary
        
        except Exception as e:
            print(f"Erreur lors du résumé NLTK: {e}")
            return text[:200] + "..." if len(text) > 200 else text
    
    @staticmethod
    def get_text_vectorization():
        """Créer une vectorisation TF-IDF des descriptions"""
        df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe()
        
        if df.empty or df['description'].isna().all():
            return {
                'vocabulary_size': 0,
                'top_terms': [],
                'vectors_shape': (0, 0)
            }
        
        # Nettoyer les textes
        texts = df['description'].fillna('').astype(str).tolist()
        cleaned_texts = []
        
        for text in texts:
            # Nettoyage basique
            text = re.sub(r'[^\w\s]', '', text.lower())
            text = re.sub(r'\d+', '', text)
            cleaned_texts.append(text)
        
        # Filtrer les textes vides
        cleaned_texts = [t for t in cleaned_texts if len(t.strip()) > 10]
        
        if len(cleaned_texts) < 2:
            return {
                'vocabulary_size': 0,
                'top_terms': [],
                'vectors_shape': (0, 0)
            }
        
        try:
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
        except Exception as e:
            print(f"Erreur vectorisation: {e}")
            return {
                'vocabulary_size': 0,
                'top_terms': [],
                'vectors_shape': (0, 0)
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
        plt.title('Distribution des Vulnerabilites par Severite')
        plt.xlabel('Severite')
        plt.ylabel('Nombre')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        charts['severity_distribution'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        # 2. Evolution temporelle
        if len(df) > 5:
            df['published_date'] = pd.to_datetime(df['published_date'])
            df['date'] = df['published_date'].dt.date
            daily_counts = df.groupby('date').size()
            
            plt.figure(figsize=(12, 6))
            daily_counts.plot(kind='line', marker='o')
            plt.title('Evolution des Vulnerabilites dans le Temps')
            plt.xlabel('Date')
            plt.ylabel('Nombre de Vulnerabilites')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            charts['temporal_evolution'] = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
        
        # 3. Top composants affectés
        component_counts = df[df['affected_component'].notna()]['affected_component'].value_counts().head(10)
        if len(component_counts) > 0:
            plt.figure(figsize=(10, 8))
            component_counts.plot(kind='pie', autopct='%1.1f%%')
            plt.title('Top 10 Composants Affectes')
            plt.ylabel('')
            plt.tight_layout()
            
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
        db = VulnerabilityDB()
        df = db.get_all_vulnerabilities_combined()
        
        summaries = []
        for _, row in df.iterrows():
            description = row['description']
            if description and len(str(description)) > 100:
                summary = VulnerabilityAnalyzer.summarize_text_with_nltk(description)
                summaries.append({
                    'cve_id': row['cve_id'] if row['cve_id'] else f"PKG-{row['affected_component']}",
                    'original_length': len(str(description)),
                    'summary': summary
                })
        
        return summaries[:10]  # Limiter à 10 pour la performance