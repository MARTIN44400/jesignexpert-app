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
# Ajoutez ces imports en haut de votre fichier jesignexpert_python_app.py
# (après vos imports existants)

# Ajoutez ces routes dans votre fichier jesignexpert_python_app.py

@app.route('/send-document-workflow', methods=['POST'])
def send_document_workflow():
    """Workflow complet d'envoi de document (Transaction + Upload + Signataires + Envoi)"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    if 'tokens' not in session:
        return jsonify({'error': 'Pas de tokens. Authentifiez-vous d\'abord.'}), 401
    
    try:
        # Récupérer les données JSON du formulaire
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400
        
        # 1. Créer la transaction
        transaction_data = {
            'object': data.get('object', '')[:45],
            'message': data.get('message', 'Document à signer')[:4000],
            'mailSender': session.get('tokens', {}).get('office', {}).get('name', 'Cabinet')[:100],
            'mailSubject': f"Signature - {data.get('object', 'Document')}"[:100],
            'notification': 'ALL',
            'locked': data.get('locked', True),
            'invitationMode': data.get('invitationMode', 'sequential'),
            'signatureRequirementMode': 'ALL'
        }
        
        logger.info(f"Création transaction workflow: {transaction_data['object']}")
        
        # Utiliser votre endpoint existant
        transaction_response = requests.post(
            f"{request.host_url.rstrip('/')}/transaction/init",
            headers={'Content-Type': 'application/json'},
            json=transaction_data,
            cookies=request.cookies  # Transmettre la session
        )
        
        if not transaction_response.ok:
            raise Exception(f"Erreur création transaction: {transaction_response.text}")
        
        transaction = transaction_response.json()
        transaction_id = transaction.get('id')
        
        if not transaction_id:
            raise Exception("Aucun ID de transaction reçu")
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'message': f'Transaction créée: {transaction_id}',
            'next_step': 'upload_document'
        })
        
    except Exception as e:
        logger.error(f"Erreur workflow envoi: {e}")
        return jsonify({'error': str(e)}), 400


@app.route('/transaction/<transaction_id>/upload-with-positions', methods=['POST'])
def upload_document_with_positions(transaction_id):
    """Upload de document avec positions de signatures automatiques"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Aucun fichier sélectionné'}), 400
        
        # Récupérer le nombre de signataires prévu
        nb_signataires = int(request.form.get('nb_signataires', 1))
        
        # Générer positions automatiques
        signature_positions = generate_signature_positions(nb_signataires)
        
        # Headers avec tokens
        headers = {
            'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']
        }
        
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        # Utiliser PUT selon la doc JeSignExpert
        url = f"{ECMA_CONFIG['base_url']}/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/uploadFile/1"
        
        files_data = {
            'file': (file.filename, file.stream, file.content_type)
        }
        
        form_data = {
            'SignFields': json.dumps(signature_positions)
        }
        
        logger.info(f"Upload vers: {url}")
        logger.info(f"Positions: {json.dumps(signature_positions)}")
        
        response = requests.put(
            url,
            headers=headers,
            files=files_data,
            data=form_data,
            timeout=60
        )
        
        logger.info(f"Upload status: {response.status_code}")
        logger.info(f"Upload response: {response.text}")
        
        if not response.ok:
            raise Exception(f"Erreur upload: {response.status_code} - {response.text}")
        
        return jsonify({
            'success': True,
            'message': 'Document uploadé avec succès',
            'positions': signature_positions,
            'result': response.json()
        })
        
    except Exception as e:
        logger.error(f"Erreur upload avec positions: {e}")
        return jsonify({'error': str(e)}), 400


@app.route('/transaction/<transaction_id>/add-signatories', methods=['POST'])
def add_multiple_signatories(transaction_id):
    """Ajouter plusieurs signataires en une fois"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        data = request.get_json()
        signatories = data.get('signatories', [])
        
        if not signatories:
            return jsonify({'error': 'Aucun signataire fourni'}), 400
        
        results = []
        
        for i, signatory in enumerate(signatories):
            signatory_data = {
                'name': signatory.get('name', ''),
                'email': signatory.get('email', ''),
                'level': signatory.get('level', i + 1),
                'positions': signatory.get('positions', [])
            }
            
            # Utiliser votre endpoint existant
            signatory_response = requests.post(
                f"{request.host_url.rstrip('/')}/transaction/{transaction_id}/signatory",
                headers={'Content-Type': 'application/json'},
                json=signatory_data,
                cookies=request.cookies
            )
            
            if signatory_response.ok:
                results.append({
                    'signatory': signatory_data['name'],
                    'status': 'success'
                })
            else:
                results.append({
                    'signatory': signatory_data['name'],
                    'status': 'error',
                    'message': signatory_response.text
                })
        
        return jsonify({
            'success': True,
            'message': f'{len([r for r in results if r["status"] == "success"])} signataires ajoutés',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Erreur ajout signataires multiples: {e}")
        return jsonify({'error': str(e)}), 400


def generate_signature_positions(nb_signataires):
    """
    Génère automatiquement des positions de signatures sur le PDF
    Positions compatibles A4 72 DPI (595x842 px)
    """
    positions = []
    
    start_y = 700  # Commencer en bas
    spacing_y = 80  # Espacement vertical
    
    for i in range(nb_signataires):
        position = {
            "order": i + 1,
            "positionX": 200,  # Centré horizontalement
            "positionY": max(100, start_y - (i * spacing_y)),  # Éviter débordement
            "page": -1,  # Dernière page (-1 = dernière page selon la doc)
            "withoutLogo": False
        }
        positions.append(position)
    
    return positions


@app.route('/transaction/<transaction_id>/complete-send', methods=['POST'])
def complete_send_workflow(transaction_id):
    """Finalise l'envoi de la transaction (après upload + signataires)"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        # Utiliser votre endpoint existant pour envoyer
        send_response = requests.post(
            f"{request.host_url.rstrip('/')}/transaction/{transaction_id}/send",
            cookies=request.cookies
        )
        
        if not send_response.ok:
            raise Exception(f"Erreur envoi final: {send_response.text}")
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'message': 'Transaction envoyée avec succès !',
            'result': send_response.json()
        })
        
    except Exception as e:
        logger.error(f"Erreur envoi final: {e}")
        return jsonify({'error': str(e)}), 400
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
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=30))
    
    def generate_hmac(self, data):
        """Génère un HMAC SHA256"""
        return hmac.new(
            self.secret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    def get_timestamp(self):
        """
        Retourne un timestamp correct en UTC avec conversion manuelle
        """
        try:
            # Récupérer l'heure du serveur ECMA
            response = requests.head(f"{self.base_url}/swagger-ui.html", timeout=10)
            if response.ok and 'Date' in response.headers:
                # Conversion manuelle sans parsedate_to_datetime
                import calendar
                from email.utils import parsedate
                
                server_date = response.headers['Date']
                # parsedate retourne un tuple, calendar.timegm le convertit en timestamp
                time_tuple = parsedate(server_date)
                utc_timestamp = calendar.timegm(time_tuple)
                timestamp_ms = utc_timestamp * 1000
                
                logger.info(f"[Timestamp UTC] Heure serveur: {server_date}")
                logger.info(f"[Timestamp UTC] Conversion manuelle: {utc_timestamp}")
                logger.info(f"[Timestamp UTC] Final (ms): {timestamp_ms}")
                
                return timestamp_ms
        except Exception as e:
            logger.error(f"[Timestamp UTC] Erreur: {e}")
        
        # Fallback avec timestamp actuel correct
        import time
        current_timestamp = int(time.time() * 1000)
        # Pour septembre 2025, le timestamp devrait être autour de 1725400000000
        if current_timestamp > 1730000000000:  # Si supérieur à novembre 2025
            logger.warning("[Timestamp UTC] Timestamp système semble incorrect, utilisation de l'heure réelle")
            # Utiliser un timestamp proche de maintenant en septembre 2025
            real_timestamp = 1725395000000  # Approximatif pour septembre 2025
            logger.info(f"[Timestamp UTC] Timestamp corrigé: {real_timestamp}")
            return real_timestamp
        
        return current_timestamp
        
    def get_auth_url(self, success_url=None, callback_url=None):
        """Génère l'URL d'authentification en effectuant un POST vers ECMA"""
        
        # Test de validation HMAC avec l'exemple de la doc
        logger.info("=== TEST DE VALIDATION HMAC ===")
        if not self.test_hmac_function():
            raise Exception("ERREUR: Fonction HMAC défectueuse - Test de validation échoué")
        logger.info("✅ Test HMAC réussi - Fonction correcte")
        logger.info("=== FIN TEST HMAC ===")
        
        # Génération des paramètres
        id_request = self.generate_id_request()
        timestamp = self.get_timestamp()
        hmac_data = f"{self.shortcut}||{id_request}||{timestamp}"
        
        # Logs détaillés pour diagnostic
        logger.info("=== PARAMÈTRES D'AUTHENTIFICATION ===")
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Shortcut: {self.shortcut}")
        logger.info(f"Secret: {self.secret[:5]}{'*' * (len(self.secret)-5)}")  # Partiellement masqué
        logger.info(f"ID Request: {id_request}")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"HMAC data: {hmac_data}")
        
        hmac_signature = self.generate_hmac(hmac_data)
        logger.info(f"HMAC généré: {hmac_signature}")
        
        # URL de l'endpoint ECMA pour POST
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/auth/{id_request}/{hmac_signature}?ts={timestamp}"
        logger.info(f"URL POST: {url}")
        
        # Body JSON comme requis par la doc ECMA
        payload = {}
        if success_url:
            payload['success_url'] = success_url
        if callback_url:
            payload['callback_url'] = callback_url
        payload['generate_hmac'] = True
        
        logger.info(f"Payload: {json.dumps(payload, indent=2)}")
        
        # Stocker l'idRequest en session
        session['auth_id_request'] = id_request
        session['auth_timestamp'] = timestamp
        session['auth_hmac'] = hmac_signature
        
        try:
            # POST vers ECMA comme requis par la documentation
            logger.info("=== APPEL API ECMA ===")
            response = requests.post(
                url, 
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            logger.info(f"Status code: {response.status_code}")
            logger.info(f"Response headers: {dict(response.headers)}")
            logger.info(f"Response content: {response.text[:500]}")
            
            if response.status_code == 400:
                logger.error("ERREUR 400 - Vérifiez:")
                logger.error("1. Que votre shortcut est correct")
                logger.error("2. Que votre secret est correct (pas d'espaces)")
                logger.error("3. Que le timestamp est dans la fenêtre ±5 minutes")
                raise Exception(f"Erreur 400 HMAC incorrect: {response.text}")
            
            if response.status_code == 404:
                logger.error("ERREUR 404 - URL ou endpoint incorrect")
                logger.error("Vérifiez que l'URL de base est correcte")
                raise Exception(f"Erreur 404 Not Found: {response.text}")
            
            if not response.ok:
                logger.error(f"Erreur ECMA: {response.status_code} - {response.text}")
                raise Exception(f"Erreur API ECMA: {response.status_code} - {response.text}")
            
            # ECMA devrait retourner l'URL d'authentification à utiliser
            auth_data = response.json()
            auth_url = auth_data.get('url') or auth_data.get('authUrl') or auth_data.get('redirectUrl')
            
            if not auth_url:
                logger.warning("ECMA n'a pas retourné d'URL, construction manuelle")
                auth_url = url
            
            logger.info(f"✅ URL d'authentification obtenue: {auth_url}")
            return auth_url
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur réseau vers ECMA: {e}")
            raise Exception(f"Impossible de contacter ECMA: {e}")
        except Exception as e:
            logger.error(f"Erreur lors de l'obtention de l'URL d'auth: {e}")
            raise
    
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
            'mailSender': 'Cabinet Expert',
            'mailSubject': f"Demande de signature - {request.json.get('name', 'Document')}",
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
            'grigri': request.json.get('grigri', False),
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
    """Ajoute un document à la transaction (utilise PUT selon la doc)"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Aucun fichier sélectionné'}), 400
        
        # Positions de signatures automatiques
        signature_positions = [
            {
                "order": 1,
                "positionX": 200,
                "positionY": 400,
                "page": -1,
                "withoutLogo": False
            }
        ]
        
        # Endpoint correct selon la doc : PUT uploadFile/{order}
        url = f"{ecma_client.base_url}/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/uploadFile/1"
        
        headers = ecma_client._get_headers()  # Tokens d'auth
        
        files_data = {
            'file': (file.filename, file.stream, file.content_type)
        }
        
        form_data = {
            'SignFields': json.dumps(signature_positions)
        }
        
        response = requests.put(
            url,
            headers=headers,
            files=files_data,
            data=form_data,
            timeout=60
        )
        
        if not response.ok:
            raise Exception(f"Erreur upload: {response.status_code} - {response.text}")
        
        return jsonify(response.json())
        
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

@app.route('/send-document')
def send_document_page():
    """Page d'envoi de document"""
    if not ecma_client:
        flash('Veuillez d\'abord configurer le secret ECMA', 'error')
        return redirect(url_for('index'))
    
    if 'tokens' not in session:
        flash('Veuillez vous authentifier', 'error') 
        return redirect(url_for('authenticate'))
    
    return render_template('send_document.html')


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

