#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Application Flask pour intégrer l'API JeSignExpert ECMA
Environnement: Préproduction
Host: https://ecma-preprod.reeliant.net
Shortcut: es_mUVuCdFh
"""

import os
import logging
import json
import uuid
import hmac
import hashlib
import time
import secrets
import string
import requests
import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Charger les variables d'environnement
load_dotenv()

# Configuration de l'app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'Uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))

# Configuration base de données
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix pour PostgreSQL URL
database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('postgres://', 'postgresql://', 1)

# Initialisation SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuration ECMA depuis .env
ECMA_CONFIG = {
    'base_url': os.getenv('ECMA_BASE_URL', 'https://ecma-preprod.reeliant.net'),
    'shortcut': os.getenv('ECMA_SHORTCUT', 'es_mUVuCdFh').strip(),
    'secret': os.getenv('ECMA_SECRET', '').strip(),
    'environment': os.getenv('ECMA_ENVIRONMENT', 'preprod')
}

# Configuration des logs
log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Créer le dossier uploads
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
    for key in ['base_url', 'shortcut', 'secret']:
        if not ECMA_CONFIG[key]:
            missing.append(f'ECMA_{key.upper()}')
    if app.secret_key == 'dev-key-change-in-production' and os.getenv('FLASK_ENV') == 'production':
        logger.warning('ATTENTION: Changez FLASK_SECRET_KEY en production!')
    if missing:
        logger.error(f"Variables d'environnement manquantes: {', '.join(missing)}")
        return False
    logger.info("Configuration .env chargée avec succès")
    return True

# Initialisation du client ECMA
ecma_client = None
def initialize_app():
    """Initialise le client ECMA si la configuration est valide"""
    global ecma_client
    if check_config():
        ecma_client = EcmaApiClient(
            ECMA_CONFIG['base_url'],
            ECMA_CONFIG['shortcut'],
            ECMA_CONFIG['secret']
        )
        logger.info("Client ECMA initialisé avec succès")

class EcmaApiClient:
    """Client pour l'API ECMA JeSignExpert"""
    
    def __init__(self, base_url, shortcut, secret):
        self.base_url = base_url.rstrip('/')
        self.shortcut = shortcut.strip()
        self.secret = secret.strip()
        logger.info(f"Initialisation EcmaApiClient - Shortcut: {repr(self.shortcut)}")

    def test_hmac_function(self):
        """Test avec l'exemple de la documentation JeSignExpert"""
        shortcut_test = "shortcut"
        id_request_test = "FCmWsIqOv8hqXBR78OHKoJSaH9Aoc0"
        timestamp_test = "1544783760000"
        secret_test = "secret"
        hmac_expected = "db2070ed2c1348f4c697797f840cb85ce07769bec64f178e61314312155210e5"
        concat_test = f"{shortcut_test}||{id_request_test}||{timestamp_test}"
        
        hmac_generated = hmac.new(
            secret_test.encode('utf-8'),
            concat_test.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.info(f"TEST HMAC - Chaîne: {repr(concat_test)}")
        logger.info(f"TEST HMAC - HMAC attendu: {hmac_expected}")
        logger.info(f"TEST HMAC - HMAC généré: {hmac_generated}")
        logger.info(f"TEST HMAC - Test réussi: {hmac_expected == hmac_generated}")
        return hmac_expected == hmac_generated

    def generate_id_request(self):
        """Génère un idRequest unique de 30 caractères alphanumériques"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(30))

    def generate_hmac(self, data):
        """Génère un HMAC SHA256 avec encodage UTF-8 strict"""
        logger.info(f"[HMAC] Chaîne brute: {repr(data)}")
        data_bytes = data.encode('utf-8', errors='strict')
        secret_bytes = self.secret.encode('utf-8', errors='strict')
        hmac_signature = hmac.new(secret_bytes, data_bytes, hashlib.sha256).hexdigest()
        logger.info(f"[HMAC] Chaîne encodée: {data_bytes}")
        logger.info(f"[HMAC] HMAC généré: {hmac_signature}")
        return hmac_signature

    def get_timestamp(self):
        """Retourne le timestamp actuel en CEST (UTC+2) en millisecondes"""
        cest_tz = datetime.timezone(datetime.timedelta(hours=2))
        timestamp_ms = int(datetime.datetime.now(cest_tz).timestamp() * 1000)
        logger.info(f"[Timestamp] CEST: {timestamp_ms} ({datetime.datetime.fromtimestamp(timestamp_ms/1000, cest_tz)})")
        return timestamp_ms

    def make_api_call(self, endpoint, method='GET', data=None, files=None):
        """Effectue un appel API générique à ECMA"""
        url = f"{self.base_url}{endpoint}"
        headers = {'Content-Type': 'application/json'} if not files else {}
        try:
            response = requests.request(method, url, json=data, files=files, headers=headers, timeout=30)
            logger.info(f"API call [{method}] {url} - Status: {response.status_code}")
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur API [{method}] {url}: {e}")
            raise

    def fetch_tokens(self):
        """Récupère les tokens après authentification"""
        id_request = session.get('auth_id_request')
        timestamp = session.get('auth_timestamp')
        hmac_signature = session.get('auth_hmac')
        if not all([id_request, timestamp, hmac_signature]):
            raise Exception("Données de session manquantes")
        endpoint = f"/editor/{self.shortcut}/token/officeAndUser/auth/{id_request}/{hmac_signature}?ts={timestamp}"
        return self.make_api_call(endpoint)

    def get_auth_url(self, success_url=None, callback_url=None):
        """Génère l'URL d'authentification en effectuant un POST vers ECMA"""
        logger.info("=== TEST DE VALIDATION HMAC ===")
        if not self.test_hmac_function():
            raise Exception("ERREUR: Fonction HMAC défectueuse")
        logger.info("✅ Test HMAC réussi")

        id_request = self.generate_id_request()
        timestamp = self.get_timestamp()
        hmac_data = f"{self.shortcut}||{id_request}||{timestamp}"
        hmac_signature = self.generate_hmac(hmac_data)

        logger.info("=== PARAMÈTRES D'AUTHENTIFICATION ===")
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Shortcut: {repr(self.shortcut)}")
        logger.info(f"Secret: {self.secret[:5]}{'*' * (len(self.secret)-5)}")
        logger.info(f"ID Request: {repr(id_request)}")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"HMAC data: {repr(hmac_data)}")
        logger.info(f"HMAC: {hmac_signature}")

        payload = {
            'success_url': success_url or 'https://jesignexpert-app.onrender.com/auth/callback',
            'generate_hmac': True
        }
        if callback_url:
            payload['callback_url'] = callback_url
        logger.info(f"Payload: {json.dumps(payload, indent=2)}")

        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/auth/{id_request}/{hmac_signature}?ts={timestamp}"
        logger.info(f"URL POST: {url}")

        session['auth_id_request'] = id_request
        session['auth_timestamp'] = timestamp
        session['auth_hmac'] = hmac_signature

        try:
            logger.info("=== APPEL API ECMA ===")
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            logger.info(f"Status code: {response.status_code}")
            logger.info(f"Response headers: {dict(response.headers)}")
            logger.info(f"Response content: {response.text[:500]}")

            if response.status_code == 400:
                logger.error("ERREUR 400 - Vérifiez shortcut, secret, timestamp")
                raise Exception(f"Erreur 400 HMAC incorrect: {response.text}")

            response.raise_for_status()
            auth_data = response.json()
            auth_url = auth_data.get('url') or auth_data.get('authUrl') or auth_data.get('redirectUrl')
            if not auth_url:
                logger.warning("ECMA n'a pas retourné d'URL, construction manuelle")
                auth_url = url
            logger.info(f"✅ URL d'authentification obtenue: {auth_url}")
            return auth_url

        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur réseau vers ECMA: {e}")
            raise

# Initialisation du client ECMA
initialize_app()

# Routes Flask
@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html', config=ECMA_CONFIG, tokens=session.get('tokens'), transactions=session.get('transactions', []))

@app.route('/config', methods=['POST'])
def configure():
    """Configure le client ECMA avec le secret"""
    global ecma_client
    secret = request.form.get('secret', '').strip()
    if not secret:
        flash('Veuillez saisir le secret ECMA', 'error')
        return redirect(url_for('index'))
    ECMA_CONFIG['secret'] = secret
    initialize_app()
    flash('Configuration ECMA mise à jour', 'success')
    return redirect(url_for('index'))

@app.route('/auth')
def authenticate():
    """Démarre le processus d'authentification"""
    if not ecma_client:
        flash('Veuillez configurer le secret ECMA', 'error')
        return redirect(url_for('index'))
    try:
        callback_base = f"https://{request.host}" if os.getenv('FLASK_ENV') == 'production' else os.getenv('CALLBACK_BASE_URL', request.host_url.rstrip('/'))
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
    """Callback après authentification"""
    if not ecma_client:
        flash('Client ECMA non configuré', 'error')
        return redirect(url_for('index'))
    try:
        if not all(k in session for k in ['auth_id_request', 'auth_timestamp', 'auth_hmac']):
            flash('Session d\'authentification expirée', 'error')
            return redirect(url_for('index'))
        tokens = ecma_client.fetch_tokens()
        if not isinstance(tokens, dict) or 'office' not in tokens or 'user' not in tokens:
            raise Exception("Structure de tokens invalide")
        session['tokens'] = tokens
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
        office_name = tokens.get('office', {}).get('name', 'Cabinet inconnu')
        flash(f'Connexion réussie ! Cabinet: {office_name}', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"❌ Erreur récupération tokens: {e}")
        flash(f'Erreur lors de l\'authentification: {e}', 'error')
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
        return redirect(url_for('index'))

@app.route('/validate-tokens')
def validate_tokens():
    """Valide les tokens actuels"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    try:
        response = ecma_client.make_api_call(f"/editor/{ECMA_CONFIG['shortcut']}/token/validateCheck")
        return jsonify({'status': 'valid', 'data': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/init', methods=['POST'])
def init_transaction():
    """Initialise une nouvelle transaction"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    try:
        transaction_data = {
            'object': request.json.get('name', 'Transaction de test')[:45],
            'message': request.json.get('message', 'Transaction créée via API')[:4000],
            'mailSender': 'Cabinet Expert',
            'mailSubject': f"Demande de signature - {request.json.get('name', 'Document')}",
            'notification': 'ALL',
            'locked': request.json.get('locked', True),
            'invitationMode': request.json.get('invitationMode', 'sequential'),
            'isHandwrittenSignatureActive': request.json.get('isHandwrittenSignatureActive', True),
            'signatureRequirementMode': 'ALL'
        }
        if request.json.get('confidential', False):
            transaction_data['confidentiality'] = []
        response = ecma_client.make_api_call(
            f"/editor/{ECMA_CONFIG['shortcut']}/transaction",
            method='POST',
            data=transaction_data
        )
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
            'isHandwrittenSignatureActive': request.json.get('isHandwrittenSignatureActive', False),
            'positions': request.json.get('positions', [])
        }
        response = ecma_client.make_api_call(
            f"/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/signatory",
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
        if 'file' not in request.files or not request.files['file'].filename:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
        file = request.files['file']
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = ecma_client.make_api_call(
            f"/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/document",
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
            f"/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/draft",
            method='POST'
        )
        return jsonify(response)
    except Exception as e:
        logger.error(f"Erreur envoi brouillon: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/send', methods=['POST'])
def send_transaction(transaction_id):
    """Lance la collecte de signatures"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    try:
        response = ecma_client.make_api_call(
            f"/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/send",
            method='POST'
        )
        return jsonify(response)
    except Exception as e:
        logger.error(f"Erreur envoi transaction: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    flash('Déconnexion réussie', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    """Gestion des erreurs 404"""
    return render_template('404.html', message="Page non trouvée"), 404

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    print("=" * 60)
    print("Application JeSignExpert ECMA")
    print(f"URL: http://localhost:{port}")
    print(f"Environment: {ECMA_CONFIG['environment']}")
    print(f"Host ECMA: {ECMA_CONFIG['base_url']}")
    print(f"Shortcut: {ECMA_CONFIG['shortcut']}")
    print(f"Secret configuré: {'Oui' if ECMA_CONFIG['secret'] else 'Non'}")
    print("=" * 60)
    
    app.run(host=host, port=port, debug=debug)
