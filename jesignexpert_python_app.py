#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Application JeSignExpert ECMA - Version Simple
Une seule page pour tout faire
"""

from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
import requests
import hashlib
import hmac
import json
import os
import logging
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'jesign-secret-key-2025')

# Configuration pour Render
app.config['SESSION_COOKIE_SECURE'] = False  # Temporairement False pour debug
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Config ECMA
ECMA_CONFIG = {
    'base_url': os.getenv('ECMA_BASE_URL', 'https://ecma-preprod.reeliant.net'),
    'shortcut': os.getenv('ECMA_SHORTCUT', 'es_mUVuCdFh'),
    'secret': os.getenv('ECMA_SECRET', '').strip()
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EcmaClient:
    def __init__(self):
        self.base_url = ECMA_CONFIG['base_url']
        self.shortcut = ECMA_CONFIG['shortcut']
        self.secret = ECMA_CONFIG['secret']
    
    def generate_hmac(self, data):
        return hmac.new(self.secret.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()
    
    def get_timestamp(self):
        import time
        return int(time.time() * 1000)
    
    def generate_id_request(self):
        import random, string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=30))

    def create_auth_url(self):
        id_request = self.generate_id_request()
        timestamp = self.get_timestamp()
        hmac_data = f"{self.shortcut}||{id_request}||{timestamp}"
        hmac_sig = self.generate_hmac(hmac_data)
        
        # Stocker dans session avec un nom unique
        session_key = f"auth_{id_request}"
        session[session_key] = {
            'id_request': id_request,
            'timestamp': timestamp,
            'hmac': hmac_sig
        }
        session['current_auth_key'] = session_key
        
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/auth/{id_request}/{hmac_sig}?ts={timestamp}"
        
        payload = {
            'success_url': "https://jesignexpert-app.onrender.com/callback",
            'generate_hmac': True
        }
        
        try:
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
            if response.ok:
                auth_data = response.json()
                return auth_data.get('url', url)
            else:
                raise Exception(f"Erreur ECMA: {response.status_code}")
        except Exception as e:
            logger.error(f"Erreur auth: {e}")
            raise

    def fetch_tokens(self):
        current_key = session.get('current_auth_key')
        if not current_key or current_key not in session:
            raise Exception("Session expirée")
        
        auth_data = session[current_key]
        url = f"{self.base_url}/editor/{self.shortcut}/token/officeAndUser/fetch/{auth_data['id_request']}/{auth_data['hmac']}?ts={auth_data['timestamp']}"
        
        response = requests.get(url)
        if response.ok:
            tokens = response.json()
            session['tokens'] = tokens
            # Nettoyer les données d'auth
            session.pop(current_key, None)
            session.pop('current_auth_key', None)
            return tokens
        else:
            raise Exception(f"Erreur fetch tokens: {response.status_code}")

    def api_call(self, endpoint, method='POST', data=None, files=None):
        if 'tokens' not in session:
            raise Exception("Non authentifié")
        
        url = f"{self.base_url}{endpoint}"
        headers = {'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']}
        
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        if data and not files:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data)
        
        response = requests.request(method=method, url=url, headers=headers, data=data, files=files)
        
        if not response.ok:
            raise Exception(f"Erreur API: {response.status_code} - {response.text}")
        
        return response.json() if response.content else {}

ecma = EcmaClient()

@app.route('/')
def index():
    return render_template('simple_app.html', 
                         tokens=session.get('tokens'),
                         config=ECMA_CONFIG)

@app.route('/auth')
def auth():
    try:
        auth_url = ecma.create_auth_url()
        return redirect(auth_url)
    except Exception as e:
        flash(f'Erreur authentification: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/callback')
def callback():
    logger.info(f"=== CALLBACK DEBUG ===")
    logger.info(f"Session keys: {list(session.keys())}")
    logger.info(f"Current auth key: {session.get('current_auth_key')}")
    logger.info(f"Query params: {request.args}")
    
    try:
        tokens = ecma.fetch_tokens()
        office_name = tokens.get('office', {}).get('name', 'Cabinet')
        flash(f'Connecté ! Cabinet: {office_name}', 'success')
        logger.info(f"Tokens stockés: {tokens.get('office', {}).get('name')}")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f'Erreur callback: {e}')
        flash(f'Erreur callback: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/send-document', methods=['POST'])
def send_document():
    try:
        if 'tokens' not in session:
            return jsonify({'error': 'Non authentifié'}), 401
        
        # 1. Créer transaction
        data = request.get_json()
        transaction_data = {
            'object': data.get('title', 'Document')[:45],
            'message': data.get('message', 'Merci de signer'),
            'mailSender': session['tokens']['office']['name'],
            'mailSubject': f"Signature - {data.get('title', 'Document')}",
            'notification': 'ALL',
            'locked': True,
            'invitationMode': data.get('mode', 'sequential'),
            'signatureRequirementMode': 'ALL'
        }
        
        transaction = ecma.api_call(f'/editor/{ECMA_CONFIG["shortcut"]}/transaction', 'POST', transaction_data)
        transaction_id = transaction['id']
        
        return jsonify({'success': True, 'transaction_id': transaction_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/upload-document/<transaction_id>', methods=['POST'])
def upload_document(transaction_id):
    try:
        file = request.files['file']
        nb_signataires = int(request.form.get('nb_signataires', 1))
        
        # Positions automatiques
        positions = []
        for i in range(nb_signataires):
            positions.append({
                "order": i + 1,
                "positionX": 200,
                "positionY": 700 - (i * 80),
                "page": -1,
                "withoutLogo": False
            })
        
        # Headers
        headers = {'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']}
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        # Upload
        url = f"{ECMA_CONFIG['base_url']}/editor/{ECMA_CONFIG['shortcut']}/transaction/{transaction_id}/uploadFile/1"
        files_data = {'file': (file.filename, file.stream, file.content_type)}
        form_data = {'SignFields': json.dumps(positions)}
        
        response = requests.put(url, headers=headers, files=files_data, data=form_data)
        
        if not response.ok:
            raise Exception(f"Erreur upload: {response.status_code}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/add-signatories/<transaction_id>', methods=['POST'])
def add_signatories(transaction_id):
    try:
        data = request.get_json()
        signatories = data.get('signatories', [])
        
        for i, signatory in enumerate(signatories):
            signatory_data = {
                'name': signatory['name'],
                'email': signatory['email'],
                'level': i + 1,
                'positions': []
            }
            
            ecma.api_call(f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/signatory', 'POST', signatory_data)
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/send-final/<transaction_id>', methods=['POST'])
def send_final(transaction_id):
    try:
        result = ecma.api_call(f'/editor/{ECMA_CONFIG["shortcut"]}/transaction/{transaction_id}/send', 'POST')
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/logout')
def logout():
    session.clear()
    flash('Déconnecté', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
