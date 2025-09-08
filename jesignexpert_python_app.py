#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Application Flask pour intégrer l'API JeSignExpert ECMA
Workflow simplifié : Envoi complet de documents
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import requests
import hashlib
import hmac
import time
import json
import os
from datetime import datetime
import logging
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration
app = Flask(__name__)

# Configuration depuis les variables d'environnement
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))

# Configuration ECMA depuis .env
ECMA_CONFIG = {
    'base_url': os.getenv('ECMA_BASE_URL', 'https://ecma-preprod.reeliant.net'),
    'shortcut': os.getenv('ECMA_SHORTCUT', 'es_mUVuCdFh'),
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


def check_config():
    """Vérifie que la configuration est complète"""
    missing = []
    
    if not ECMA_CONFIG['base_url']:
        missing.append('ECMA_BASE_URL')
    if not ECMA_CONFIG['shortcut']:
        missing.append('ECMA_SHORTCUT')
    if not ECMA_CONFIG['secret']:
        missing.append('ECMA_SECRET')
    
    if missing:
        logger.error(f"Variables d'environnement manquantes: {', '.join(missing)}")
        return False
    
    logger.info("Configuration .env chargée avec succès")
    return True


class EcmaApiClient:
    """Client pour l'API ECMA JeSignExpert"""
    
    def __init__(self, base_url, shortcut, secret):
        self.base_url = base_url
        self.shortcut = shortcut
        self.secret = secret.strip()
        
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
        """Retourne un timestamp correct en UTC"""
        try:
            # Récupérer l'heure du serveur ECMA
            response = requests.head(f"{self.base_url}/swagger-ui.html", timeout=10)
            if response.ok and 'Date' in response.headers:
                import calendar
                from email.utils import parsedate
                
                server_date = response.headers['Date']
                time_tuple = parsedate(server_date)
                utc_timestamp = calendar.timegm(time_tuple)
                timestamp_ms = utc_timestamp * 1000
                
                logger.info(f"[Timestamp UTC] Final (ms): {timestamp_ms}")
                return timestamp_ms
        except Exception as e:
            logger.error(f"[Timestamp UTC] Erreur: {e}")
        
        # Fallback avec timestamp actuel
        import time
        current_timestamp = int(time.time() * 1000)
        return current_timestamp
        
    def get_auth_url(self, success_url=None):
        """Génère l'URL d'authentification"""
        
        # Test HMAC
        if not self.test_hmac_function():
            raise Exception("ERREUR: Fonction HMAC défectueuse")
        
        # Génération des paramètres
        id_request = self.generate_id_request()
        timestamp = self.get_timestamp()
        hmac_data = f"{self.shortcut}||{id_request}||{timestamp}"
        hmac_signature = self.generate_hmac(hmac_data)
        
        # URL de l'endpoint ECMA
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/auth/{id_request}/{hmac_signature}?ts={timestamp}"
        
        # Body JSON
        payload = {}
        if success_url:
            payload['success_url'] = success_url
        payload['generate_hmac'] = True
        
        # Stocker l'idRequest en session
        session['auth_id_request'] = id_request
        session['auth_timestamp'] = timestamp
        session['auth_hmac'] = hmac_signature
        
        try:
            response = requests.post(
                url, 
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if not response.ok:
                raise Exception(f"Erreur API ECMA: {response.status_code} - {response.text}")
            
            auth_data = response.json()
            auth_url = auth_data.get('url')
            
            if not auth_url:
                auth_url = url
            
            logger.info(f"URL d'authentification obtenue: {auth_url}")
            return auth_url
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Impossible de contacter ECMA: {e}")
    
    def fetch_tokens(self):
        """Récupère les tokens après authentification"""
        if not all(k in session for k in ['auth_id_request', 'auth_timestamp', 'auth_hmac']):
            raise Exception("Aucune session d'authentification trouvée")
        
        id_request = session['auth_id_request']
        timestamp = session['auth_timestamp']
        hmac_signature = session['auth_hmac']
        
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/fetch/{id_request}/{hmac_signature}?ts={timestamp}"
        
        try:
            response = requests.get(url, timeout=30)
            
            if response.status_code == 404:
                raise Exception("Session d'authentification expirée. Veuillez recommencer.")
            
            if not response.ok:
                raise Exception(f"Erreur API: {response.status_code} - {response.text}")
            
            tokens = response.json()
            logger.info("Tokens récupérés avec succès")
            return tokens
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur de connexion à ECMA: {e}")
    
    def make_api_call(self, endpoint, method='GET', data=None):
        """Effectue un appel API avec les tokens stockés en session"""
        if 'tokens' not in session:
            raise Exception("Pas de tokens disponibles. Veuillez vous authentifier.")
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']
        }
        
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        if data:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data)
        
        logger.info(f"API Call: {method} {url}")
        
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data
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
        logger.info("Client ECMA initialisé")

# Initialiser au démarrage
with app.app_context():
    initialize_app()


def generate_signature_positions(nb_signataires):
    """Génère automatiquement des positions de signatures sur le PDF"""
    positions = []
    start_y = 700
    spacing_y = 80
    
    for i in range(nb_signataires):
        position = {
            "order": i + 1,
            "positionX": 200,
            "positionY": max(100, start_y - (i * spacing_y)),
            "page": -1,
            "withoutLogo": False
        }
        positions.append(position)
    
    return positions


# ===== ROUTES =====

@app.route('/', methods=['GET', 'POST'])
def index():
    """Page d'accueil"""
    return render_template('index.html', 
                         config=ECMA_CONFIG,
                         tokens=session.get('tokens'),
                         secret_configured=bool(ECMA_CONFIG['secret']))

@app.route('/auth')
def authenticate():
    """Démarre le processus d'authentification"""
    if not ecma_client:
        flash('Veuillez d\'abord configurer le secret ECMA', 'error')
        return redirect(url_for('index'))
    
    try:
        # URL de callback fixe pour Render
        success_url = "https://jesignexpert-app.onrender.com/auth/callback"
        auth_url = ecma_client.get_auth_url(success_url=success_url)
        
        logger.info(f"Redirection vers: {auth_url}")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Erreur authentification: {e}")
        flash(f'Erreur d\'authentification: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/auth/callback')
def auth_callback():
    """Callback après authentification ComptExpert"""
    if not ecma_client:
        flash('Client ECMA non configuré', 'error')
        return redirect(url_for('index'))
    
    try:
        tokens = ecma_client.fetch_tokens()
        
        if not isinstance(tokens, dict) or 'office' not in tokens:
            raise Exception("Structure de tokens invalide reçue d'ECMA")
        
        session['tokens'] = tokens
        
        # Nettoyer les données d'auth temporaires
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
        
        office_name = tokens.get('office', {}).get('name', 'Cabinet inconnu')
        flash(f'Connexion réussie ! Cabinet: {office_name}', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Erreur récupération tokens: {e}")
        flash(f'Erreur lors de l\'authentification: {e}', 'error')
        
        # Nettoyer la session en cas d'erreur
        for key in ['auth_id_request', 'auth_timestamp', 'auth_hmac']:
            session.pop(key, None)
            
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

@app.route('/send-document-workflow', methods=['POST'])
def send_document_workflow():
    """Workflow complet d'envoi de document - Étape 1: Créer transaction"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    if 'tokens' not in session:
        return jsonify({'error': 'Pas de tokens. Authentifiez-vous d\'abord.'}), 401
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400
        
        # Créer la transaction via l'API ECMA
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
        
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction',
            method='POST',
            data=transaction_data
        )
        
        transaction_id = response.get('id')
        if not transaction_id:
            raise Exception("Aucun ID de transaction reçu")
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'message': f'Transaction créée: {transaction_id}'
        })
        
    except Exception as e:
        logger.error(f"Erreur workflow envoi: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/upload-with-positions', methods=['POST'])
def upload_document_with_positions(transaction_id):
    """Workflow complet d'envoi de document - Étape 2: Upload document"""
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
        
        # Upload via PUT selon la doc JeSignExpert
        url = f"{ECMA_CONFIG['base_url']}/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/uploadFile/1"
        
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
    """Workflow complet d'envoi de document - Étape 3: Ajouter signataires"""
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
            
            try:
                response = ecma_client.make_api_call(
                    f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/signatory',
                    method='POST',
                    data=signatory_data
                )
                
                results.append({
                    'signatory': signatory_data['name'],
                    'status': 'success'
                })
            except Exception as e:
                results.append({
                    'signatory': signatory_data['name'],
                    'status': 'error',
                    'message': str(e)
                })
        
        return jsonify({
            'success': True,
            'message': f'{len([r for r in results if r["status"] == "success"])} signataires ajoutés',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Erreur ajout signataires multiples: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transaction/<transaction_id>/complete-send', methods=['POST'])
def complete_send_workflow(transaction_id):
    """Workflow complet d'envoi de document - Étape 4: Finaliser envoi"""
    if not ecma_client:
        return jsonify({'error': 'Client non configuré'}), 400
    
    try:
        response = ecma_client.make_api_call(
            f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/send',
            method='POST'
        )
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'message': 'Transaction envoyée avec succès !',
            'result': response
        })
        
    except Exception as e:
        logger.error(f"Erreur envoi final: {e}")
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
    print("Application JeSignExpert ECMA - Version Simplifiée")
    print("=" * 60)
    print(f"URL: http://localhost:{port}")
    print(f"Environment: {ECMA_CONFIG['environment']}")
    print(f"Host ECMA: {ECMA_CONFIG['base_url']}")
    print(f"Shortcut: {ECMA_CONFIG['shortcut']}")
    print(f"Secret configuré: {'Oui' if ECMA_CONFIG['secret'] else 'Non'}")
    print("=" * 60)
    
    app.run(host=host, port=port, debug=debug)
