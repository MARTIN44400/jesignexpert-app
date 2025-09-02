#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Application Flask pour intégrer l'API JeSignExpert ECMA
Environnement: Préproduction
Host: https://ecma-preprod.reeliant.net
Shortcut: es_mUVuCdFh
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import requests
import hashlib
import hmac
import time
import json
import uuid
import os
from datetime import datetime, timedelta
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Charger les variables d'environnement
load_dotenv()

# Configuration
app = Flask(__name__)

# Configuration depuis les variables d'environnement
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))

# Configuration base de données
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix pour Railway PostgreSQL URL
database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('postgres://', 'postgresql://', 1)

# Initialisation SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuration ECMA depuis .env
ECMA_CONFIG = {
    'base_url': os.getenv('ECMA_BASE_URL', 'https://ecma-preprod.reeliant.net'),
    'shortcut': os.getenv('ECMA_SHORTCUT', 'es_mUVuCdFh'),
    'secret': os.getenv('ECMA_SECRET', '').strip(),  # Supprime les espaces
    'environment': os.getenv('ECMA_ENVIRONMENT', 'preprod')
}

# Configuration des logs
log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Créer le dossier uploads s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Modèles de données
class Transaction(db.Model):
    """Modèle pour stocker les transactions"""
    __tablename__ = 'transactions'
    
    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='draft')
    confidential = db.Column(db.Boolean, default=False)
    invitation_mode = db.Column(db.String(50), default='sequential')
    ecma_transaction_id = db.Column(db.String(100))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user_email = db.Column(db.String(200))
    office_name = db.Column(db.String(200))

class Signatory(db.Model):
    """Modèle pour les signataires"""
    __tablename__ = 'signatories'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(100), db.ForeignKey('transactions.id'), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    level = db.Column(db.Integer, default=1)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Vérification de la configuration
def check_config():
    """Vérifie que la configuration est complète"""
    missing = []
    
    if not ECMA_CONFIG['base_url']:
        missing.append('ECMA_BASE_URL')
    if not ECMA_CONFIG['shortcut']:
        missing.append('ECMA_SHORTCUT')
    if not ECMA_CONFIG['secret']:
        missing.append('ECMA_SECRET')
    
    if app.secret_key == 'dev-key-change-in-production' and os.getenv('FLASK_ENV') == 'production':
        logger.warning('ATTENTION: Changez FLASK_SECRET_KEY en production!')
    
    if missing:
        logger.error(f"Variables d'environnement manquantes: {', '.join(missing)}")
        logger.error("Copiez .env.example vers .env et remplissez vos valeurs")
        return False
    
    logger.info("Configuration .env chargée avec succès")
    return True

class EcmaApiClient:
    """Client pour l'API ECMA JeSignExpert"""
    
    def __init__(self, base_url, shortcut, secret):
        self.base_url = base_url
        self.shortcut = shortcut
        self.secret = secret.strip()  # Nettoyage du secret
        
    def test_connectivity(self):
        """Test de connectivité initial avec l'URL de base"""
        try:
            url = f"{self.base_url}/swagger-ui.html"  # Interface Swagger connue
            response = requests.get(url, timeout=10)
            logger.info(f"Test connectivité: {response.status_code}")
            return response.ok
        except Exception as e:
            logger.error(f"Test connectivité échoué: {e}")
            return False
    
    def test_hmac_function(self):
        """Test avec l'exemple de la documentation JeSignExpert"""
        # Valeurs exactes de la doc
        shortcut_test = "shortcut"
        id_request_test = "FCmWsIqOv8hqXBR78OHKoJSaH9Aoc0"
        timestamp_test = "1544783760000"
        secret_test = "secret"
        
        # HMAC attendu selon la doc
        hmac_expected = "db2070ed2c1348f4c697797f840cb85ce07769bec64f178e61314312155210e5"
        
        # Construction de la chaîne
        concat_test = f"{shortcut_test}||{id_request_test}||{timestamp_test}"
        
        # Test de votre fonction
        hmac_generated = hmac.new(
            secret_test.encode('utf-8'),
            concat_test.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.info(f"TEST HMAC - Chaîne: {concat_test}")
        logger.info(f"TEST HMAC - HMAC attendu: {hmac_expected}")
        logger.info(f"TEST HMAC - HMAC généré: {hmac_generated}")
        logger.info(f"TEST HMAC - Test réussi: {hmac_expected == hmac_generated}")
        
        return hmac_expected == hmac_generated
    
    def generate_id_request(self):
        """Génère un idRequest unique de 30 caractères alphanumériques"""
        import secrets
        import string
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(30))
    
    def generate_hmac(self, data):
        """Génère un HMAC SHA256"""
        return hmac.new(
            self.secret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        


     def get_timestamp(self):
         # Essayer plusieurs sources externes pour garantir un timestamp UTC précis
         for url in ['https://timeapi.io/api/Time/current/zone?timeZone=UTC', 
                    'http://worldtimeapi.org/api/timezone/UTC']:
             try:
                 response = requests.get(url, timeout=5)
                 if response.ok:
                     time_data = response.json()
                     if 'dateTime' in time_data:  # timeapi.io
                         external_timestamp = int(datetime.fromisoformat(time_data['dateTime'].replace('Z', '')).timestamp() * 1000)
                         logger.info(f"Timestamp externe ({url}): {external_timestamp} ms")
                         logger.info(f"Heure externe UTC: {time_data['dateTime']}")
                         return external_timestamp
                     elif 'unixtime' in time_data:  # worldtimeapi.org
                         external_timestamp = int(time_data['unixtime'] * 1000)
                         logger.info(f"Timestamp externe ({url}): {external_timestamp} ms")
                         logger.info(f"Heure externe UTC: {datetime.utcfromtimestamp(time_data['unixtime']).strftime('%Y-%m-%d %H:%M:%S')}")
                         return external_timestamp
             except Exception as e:
                 logger.warning(f"Erreur synchronisation externe ({url}): {e}")
         
         # Fallback sur le système, avec vérification
         system_timestamp = int(time.time() * 1000)
         system_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
         logger.info(f"Timestamp système: {system_timestamp} ms")
         logger.info(f"Heure système UTC: {system_utc}")
         
         # Vérifier si le timestamp est dans une plage raisonnable
         expected_timestamp = 1756848000000  # 02/09/2025 20:00 UTC
         if abs(system_timestamp - expected_timestamp) > 900000:  # ±15 min
             logger.error(f"Timestamp système incohérent: {system_timestamp} ms, attendu ~{expected_timestamp} ms")
             raise Exception("Horloge système désynchronisée")
         
         return system_timestamp
    
    def fetch_tokens(self):
        """Récupère les tokens après authentification"""
        if not all(k in session for k in ['auth_id_request', 'auth_timestamp', 'auth_hmac']):
            raise Exception("Aucune session d'authentification trouvée")
        
        id_request = session['auth_id_request']
        timestamp = session['auth_timestamp']
        hmac_signature = session['auth_hmac']
        
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/fetch/{id_request}/{hmac_signature}?ts={timestamp}"
        
        try:
            logger.info(f"Récupération des tokens: {url}")
            response = requests.get(url, timeout=30)
            
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Response: {response.text[:500]}")
            
            if response.status_code == 404:
                raise Exception("Session d'authentification expirée. Veuillez recommencer.")
            
            if not response.ok:
                raise Exception(f"Erreur API: {response.status_code} - {response.text}")
            
            tokens = response.json()
            
            # Validation renforcée de la structure des tokens
            if not (isinstance(tokens, dict) and 
                    'office' in tokens and tokens['office'].get('token') and 
                    'user' in tokens and tokens['user'].get('token')):
                raise Exception("Structure de tokens invalide reçue d'ECMA")
            
            logger.info("✅ Tokens récupérés avec succès")
            return tokens
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur de connexion à ECMA: {e}")
    
    def make_api_call(self, endpoint, method='GET', data=None, files=None):
        """Effectue un appel API avec les tokens stockés en session"""
        if 'tokens' not in session:
            raise Exception("Pas de tokens disponibles. Veuillez vous authentifier.")
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']
        }
        
        # Ajouter le token utilisateur s'il existe
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        if data and not files:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data)
        
        logger.info(f"API Call: {method} {url}")
        
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            files=files
        )
        
        logger.info(f"Headers envoyés: {dict((k, v[:20] + '...' if len(v) > 20 else v) for k, v in headers.items())}")
        
        if response.status_code == 403:
            logger.error("Erreur 403: Tokens invalides ou révoqués")
            raise Exception("Tokens invalides. Veuillez vous réauthentifier.")
        
        if not response.ok:
            logger.error(f"API Error: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        return response.json() if response.content else {}

# Instance globale du client API
ecma_client = None

def initialize_app():
    """Initialisation de l'application"""
    global ecma_client
    
    if check_config() and ECMA_CONFIG['secret']:
        ecma_client = EcmaApiClient(
            ECMA_CONFIG['base_url'],
            ECMA_CONFIG['shortcut'],
            ECMA_CONFIG['secret']
        )
        logger.info("🚀 Client ECMA initialisé")

# Initialiser au démarrage
with app.app_context():
    initialize_app()

# Commandes CLI pour la base de données
@app.cli.command()
def init_db():
    """Initialise la base de données"""
    db.create_all()
    print("✅ Base de données initialisée")

@app.cli.command()
def reset_db():
    """Remet à zéro la base de données"""
    db.drop_all()
    db.create_all()
    print("✅ Base de données réinitialisée")

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    """Page d'accueil"""
    global ecma_client
    if not ecma_client and ECMA_CONFIG['secret']:
        initialize_app()
    
    return render_template('index.html', 
                         config=ECMA_CONFIG,
                         tokens=session.get('tokens'),
                         transactions=session.get('transactions', []),
                         secret_configured=bool(ECMA_CONFIG['secret']))

@app.route('/config', methods=['POST'])
def configure():
    """Configure le client ECMA avec le secret"""
    global ecma_client
    
    secret = request.form.get('secret', '').strip()
    if not secret:
        flash('Veuillez saisir le secret ECMA', 'error')
        return redirect(url_for('index'))
    
    ECMA_CONFIG['secret'] = secret
    ecma_client = EcmaApiClient(
        ECMA_CONFIG['base_url'],
        ECMA_CONFIG['shortcut'],
        secret
    )
    
    logger.info("🔧 Configuration ECMA mise à jour")
    flash('Configuration ECMA mise à jour avec succès', 'success')
    return redirect(url_for('index'))

@app.route('/auth')
def authenticate():
    """Démarre le processus d'authentification"""
    if not ecma_client:
        flash('Veuillez d\'abord configurer le secret ECMA', 'error')
        return redirect(url_for('index'))
    
    try:
        # Forcer HTTPS pour les callbacks en production
        if os.getenv('FLASK_ENV') == 'production':
            callback_base = f"https://{request.host}"
        else:
            callback_base = os.getenv('CALLBACK_BASE_URL', request.host_url.rstrip('/'))
        
        success_url = f"{callback_base}{url_for('auth_callback')}"
        
        auth_url = ecma_client.get_auth_url(success_url=success_url)
        
        logger.info(f"🔀 Redirection vers: {auth_url}")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"⚠ Erreur authentification: {e}")
        flash(f'Erreur d\'authentification: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/auth/callback')
def auth_callback():
    """Callback après authentification ComptExpert"""
    if not ecma_client:
        flash('Client ECMA non configuré', 'error')
        return redirect(url_for('index'))
    
    try:
        if not all(k in session for k in ['auth_id_request', 'auth_timestamp', 'auth_hmac']):
            flash('Session d\'authentification expirée. Veuillez recommencer.', 'error')
            return redirect(url_for('index'))
        
        tokens = ecma_client.fetch_tokens()
        
        if not isinstance(tokens, dict) or 'office' not in tokens or 'user' not in tokens:
            raise Exception("Structure de tokens invalide reçue d'ECMA")
        
        session['tokens'] = tokens
        
        # Nettoyer les données d'auth temporaires
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
        
        office_name = tokens.get('office', {}).get('name', 'Cabinet inconnu')
        flash(f'Connexion réussie ! Cabinet: {office_name}', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"❌ Erreur récupération tokens: {e}")
        flash(f'Erreur lors de l\'authentification: {e}', 'error')
        
        # Nettoyer la session en cas d'erreur
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
            
        return redirect(url_for('index'))

@app.route('/validate-tokens')
def validate_tokens():
    """Valide les tokens actuels"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        response = ecma_client.make_api_call(f'/editor/{ECMA_CONFIG["shortcut"]}/token/validateCheck')
        return jsonify({'status': 'valid', 'data': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/init', methods=['POST'])
def init_transaction():
    """Initialise une nouvelle transaction avec le bon format JeSignExpert"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        # Format selon la documentation JeSignExpert section 4.1.1
        transaction_data = {
            'object': request.json.get('name', 'Transaction de test')[:45],  # Max 45 chars
            'message': request.json.get('message', 'Transaction créée depuis l\'API Python')[:4000],
            'mailSender': session.get('tokens', {}).get('office', {}).get('name', 'Cabinet Expert')[:100],
            'mailSubject': f"Demande de signature - {request.json.get('name', 'Document')}"[:100],
            'notification': 'ALL',
            'locked': request.json.get('locked', True),
            'invitationMode': request.json.get('invitationMode', 'sequential'),
            'isHandwrittenSignatureActive': True,
            'signatureRequirementMode': 'ALL'
        }
        
        # Ajouter confidentialité si spécifiée
        if request.json.get('confidential', False):
            transaction_data['confidentiality'] = []  # Vide pour non confidentiel, ou emails pour confidentiel
        
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction',
            method='POST',
            data=transaction_data
        )
        
        # Sauvegarder en BDD
        try:
            trans = Transaction(
                id=response.get('id', str(uuid.uuid4())),
                name=request.json.get('name', 'Transaction'),
                type='signature',
                confidential=request.json.get('confidential', False),
                invitation_mode=request.json.get('invitationMode', 'sequential'),
                ecma_transaction_id=response.get('id'),
                user_email=session.get('tokens', {}).get('user', {}).get('email'),
                office_name=session.get('tokens', {}).get('office', {}).get('name')
            )
            db.session.add(trans)
            db.session.commit()
        except Exception as db_error:
            logger.error(f"Erreur sauvegarde BDD: {db_error}")
        
        # Stocker en session
        session['current_transaction'] = response
        transactions = session.get('transactions', [])
        transactions.append(response)
        session['transactions'] = transactions
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Erreur init transaction: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/signatory', methods=['POST'])
def add_signatory(transaction_id):
    """Ajoute un signataire à la transaction"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        data = {
            'email': request.json.get('email'),
            'name': request.json.get('name'),
            'level': int(request.json.get('level', 1)),
            'isHandwrittenSignatureActive': request.json.get('grigri', True),  # Correction: remplace grigri déprécié
            'positions': request.json.get('positions', [])
        }
        
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/signatory',
            method='POST',
            data=data
        )
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Erreur ajout signataire: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/document', methods=['POST'])
def add_document(transaction_id):
    """Ajoute un document à la transaction"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Aucun fichier sélectionné'}), 400
        
        files = {
            'file': (file.filename, file.stream, file.content_type)
        }
        
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/document',
            method='POST',
            files=files
        )
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Erreur ajout document: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/draft', methods=['POST'])
def send_draft(transaction_id):
    """Envoie la transaction en mode brouillon"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/draft',
            method='POST'
        )
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/send', methods=['POST'])
def send_transaction(transaction_id):
    """Lance la collecte de signatures"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/send',
            method='POST'
        )
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    flash('Déconnexion réussie', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>404 - Page non trouvée</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>Page non trouvée</h1>
        <p>La page demandée n'existe pas.</p>
        <a href="/" style="color: #667eea;">Retour à l'accueil</a>
    </body>
    </html>
    ''', 404

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    print("=" * 60)
    print("Application JeSignExpert ECMA")
    print("=" * 60)
    print(f"URL: http://localhost:{port}")
    print(f"Environment: {ECMA_CONFIG['environment']}")
    print(f"Host ECMA: {ECMA_CONFIG['base_url']}")
    print(f"Shortcut: {ECMA_CONFIG['shortcut']}")
    print(f"Secret configuré: {'Oui' if ECMA_CONFIG['secret'] else 'Non'}")
    print("=" * 60)
    
    app.run(host=host, port=port, debug=debug)
