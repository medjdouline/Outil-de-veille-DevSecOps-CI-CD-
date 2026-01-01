import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Configuration de base"""
    SECRET_KEY = 'ta-clé-secrète-change-moi-en-production'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, "data", "vulnerabilities.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    
    # Configuration session
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

class DevelopmentConfig(Config):
    """Config pour développement"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Config pour production"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Config pour tests"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
