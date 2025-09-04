#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module d'envoi de documents JeSignExpert
Workflow complet : Transaction -> Upload -> Signataires -> Envoi
"""

import requests
import json
import logging
from flask import session

logger = logging.getLogger(__name__)


class DocumentSender:
    """Gestionnaire d'envoi de documents JeSignExpert"""
    
    def __init__(self, base_url, shortcut):
        self.base_url = base_url
        self.shortcut = shortcut
    
    def _get_headers(self):
        """Récupère les headers d'authentification depuis la session"""
        if 'tokens' not in session:
            raise Exception("Pas de tokens disponibles. Veuillez vous authentifier.")
        
        headers = {
            'JSE-EDITOR-TOKEN-OFFICE': session['tokens']['office']['token']
        }
        
        if 'user' in session['tokens'] and session['tokens']['user'].get('token'):
            headers['JSE-EDITOR-TOKEN-USER'] = session['tokens']['user']['token']
        
        return headers
    
    def create_transaction(self, document_info):
        """
        Étape 1 : Initialiser une transaction
        
        Args:
            document_info (dict): {
                'object': 'Titre (max 45 chars)',
                'message': 'Message explicatif',
                'invitation_mode': 'sequential|parallel',
                'locked': True/False,
                'notification': 'ALL|NONE'
            }
        
        Returns:
            dict: {'id': 'transaction_id'}
        """
        url = f"{self.base_url}/editor/{self.shortcut}/transaction"
        
        # Préparer les données selon la doc JeSignExpert
        payload = {
            'object': document_info['object'][:45],  # Max 45 caractères
            'message': document_info.get('message', 'Document à signer')[:4000],
            'mailSender': session.get('tokens', {}).get('office', {}).get('name', 'Cabinet')[:100],
            'mailSubject': f"Signature - {document_info['object']}"[:100],
            'notification': document_info.get('notification', 'ALL'),
            'locked': document_info.get('locked', True),
            'invitationMode': document_info.get('invitation_mode', 'sequential'),
            'signatureRequirementMode': 'ALL'
        }
        
        logger.info(f"Création transaction: {payload['object']}")
        
        try:
            response = requests.post(
                url,
                headers={**self._get_headers(), 'Content-Type': 'application/json'},
                json=payload,
                timeout=30
            )
            
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Response: {response.text}")
            
            if response.status_code == 403:
                raise Exception("Tokens expirés. Veuillez vous réauthentifier.")
            
            if not response.ok:
                raise Exception(f"Erreur création transaction: {response.status_code} - {response.text}")
            
            result = response.json()
            transaction_id = result.get('id')
            
            if not transaction_id:
                raise Exception("Aucun ID de transaction reçu")
            
            logger.info(f"Transaction créée: {transaction_id}")
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur réseau lors de la création: {e}")
    
    def upload_document(self, transaction_id, file_data, signature_positions, order=1):
        """
        Étape 2 : Uploader le document PDF avec positions de signatures
        
        Args:
            transaction_id (str): ID de la transaction
            file_data: Fichier (Flask FileStorage ou tuple (filename, content, content_type))
            signature_positions (list): Liste des positions de signatures
            order (int): Ordre du document (1, 2, 3...)
        
        Returns:
            dict: Réponse de l'API
        """
        url = f"{self.base_url}/editor/{self.shortcut}/transaction/{transaction_id}/uploadFile/{order}"
        
        # Préparer SignFields selon la doc
        sign_fields = json.dumps(signature_positions)
        
        # Préparer le fichier
        if hasattr(file_data, 'filename'):  # Flask FileStorage
            files = {
                'file': (file_data.filename, file_data.stream, file_data.content_type)
            }
        else:  # Tuple
            files = {'file': file_data}
        
        # Données du formulaire
        data = {
            'SignFields': sign_fields
        }
        
        logger.info(f"Upload document pour transaction {transaction_id}")
        logger.info(f"Positions signatures: {sign_fields}")
        
        try:
            response = requests.put(
                url,
                headers=self._get_headers(),
                files=files,
                data=data,
                timeout=60
            )
            
            logger.info(f"Upload status: {response.status_code}")
            logger.info(f"Upload response: {response.text}")
            
            if not response.ok:
                raise Exception(f"Erreur upload document: {response.status_code} - {response.text}")
            
            result = response.json()
            logger.info("Document uploadé avec succès")
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur réseau lors de l'upload: {e}")
    
    def add_signatory(self, transaction_id, signatory_info):
        """
        Étape 3 : Ajouter un signataire
        
        Args:
            transaction_id (str): ID de la transaction
            signatory_info (dict): {
                'name': 'Nom complet',
                'email': 'email@domain.com',
                'level': 1,  # Niveau de signature
                'positions': []  # Positions spécifiques (optionnel)
            }
        
        Returns:
            dict: Réponse de l'API
        """
        url = f"{self.base_url}/editor/{self.shortcut}/transaction/{transaction_id}/signatory"
        
        payload = {
            'name': signatory_info['name'],
            'email': signatory_info['email'],
            'level': signatory_info.get('level', 1),
            'positions': signatory_info.get('positions', [])
        }
        
        logger.info(f"Ajout signataire: {payload['name']} ({payload['email']})")
        
        try:
            response = requests.post(
                url,
                headers={**self._get_headers(), 'Content-Type': 'application/json'},
                json=payload,
                timeout=30
            )
            
            logger.info(f"Signataire status: {response.status_code}")
            
            if not response.ok:
                raise Exception(f"Erreur ajout signataire: {response.status_code} - {response.text}")
            
            result = response.json()
            logger.info("Signataire ajouté avec succès")
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur réseau lors de l'ajout signataire: {e}")
    
    def send_transaction(self, transaction_id):
        """
        Étape 4 : Envoyer la transaction (finaliser)
        
        Args:
            transaction_id (str): ID de la transaction
        
        Returns:
            dict: Réponse de l'API
        """
        url = f"{self.base_url}/editor/{self.shortcut}/transaction/{transaction_id}/send"
        
        logger.info(f"Envoi transaction: {transaction_id}")
        
        try:
            response = requests.post(
                url,
                headers=self._get_headers(),
                timeout=30
            )
            
            logger.info(f"Envoi status: {response.status_code}")
            logger.info(f"Envoi response: {response.text}")
            
            if not response.ok:
                raise Exception(f"Erreur envoi transaction: {response.status_code} - {response.text}")
            
            result = response.json()
            logger.info("Transaction envoyée avec succès")
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur réseau lors de l'envoi: {e}")
    
    def send_complete_document(self, document_info, file_data, signatories):
        """
        Workflow complet d'envoi de document
        
        Args:
            document_info (dict): Infos de la transaction
            file_data: Fichier à envoyer
            signatories (list): Liste des signataires
        
        Returns:
            dict: Résultat final avec transaction_id
        """
        try:
            # 1. Créer la transaction
            transaction = self.create_transaction(document_info)
            transaction_id = transaction['id']
            
            # 2. Générer les positions de signatures automatiquement
            signature_positions = self.generate_signature_positions(len(signatories))
            
            # 3. Uploader le document
            self.upload_document(transaction_id, file_data, signature_positions)
            
            # 4. Ajouter les signataires
            for i, signatory in enumerate(signatories):
                signatory['level'] = i + 1  # Niveau séquentiel
                self.add_signatory(transaction_id, signatory)
            
            # 5. Envoyer la transaction
            send_result = self.send_transaction(transaction_id)
            
            return {
                'transaction_id': transaction_id,
                'status': 'sent',
                'signatories_count': len(signatories),
                'result': send_result
            }
            
        except Exception as e:
            logger.error(f"Erreur workflow complet: {e}")
            raise
    
    def generate_signature_positions(self, nb_signataires):
        """
        Génère automatiquement des positions de signatures sur le PDF
        
        Args:
            nb_signataires (int): Nombre de signataires
        
        Returns:
            list: Positions de signatures
        """
        positions = []
        
        # Dimensions A4 72 DPI: 595x842 px
        # Zone de signature: 200x50 px
        # Positions utilisables: X(0-385), Y(0-792)
        
        start_y = 700  # Commencer en bas
        spacing_y = 80  # Espacement vertical
        
        for i in range(nb_signataires):
            position = {
                "order": i + 1,
                "positionX": 200,  # Centré horizontalement
                "positionY": max(100, start_y - (i * spacing_y)),  # Éviter débordement
                "page": -1,  # Dernière page
                "withoutLogo": False
            }
            positions.append(position)
        
        return positions
