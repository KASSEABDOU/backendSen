# routes/auth.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from datetime import datetime, timezone, timedelta
import os
import traceback

from models import db, User, UserType, AuditLog, TokenBlacklist
from utils.decorators import role_required, limiter 
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """Inscription d'un nouvel utilisateur"""
    try:
        # 🔍 LOG 1: Démarré
        print(f"\n=== REGISTER CALLED ===")
        print(f"Time: {datetime.now()}")
        print(f"Method: {request.method}")
        print(f"Content-Type: {request.headers.get('Content-Type')}")
        print(f"Headers: {dict(request.headers)}")
        
        # Récupérer les données JSON
        data = request.get_json()
        print(f"Raw data received: {data}")
        
        # 🔍 LOG 2: Validation
        if not data:
            print("ERROR: No JSON data received")
            return jsonify({'error': 'Aucune donnée JSON reçue'}), 400
        
        # Validation des données
        required_fields = ['email', 'password', 'nom', 'prenom']
        for field in required_fields:
            if field not in data:
                print(f"ERROR: Missing field '{field}'")
                print(f"Available fields: {list(data.keys())}")
                return jsonify({'error': f'Le champ {field} est requis'}), 400
        
        print(f"✅ All required fields present")
        
        # Vérifier si l'email existe déjà
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            print(f"ERROR: Email already exists: {data['email']}")
            return jsonify({'error': 'Cet email est déjà utilisé'}), 400
        
        print(f"✅ Email is unique")
        
        # Valider l'email
        if not User.validate_email(data['email']):
            print(f"ERROR: Invalid email format: {data['email']}")
            return jsonify({'error': 'Format d\'email invalide'}), 400
        
        print(f"✅ Email format is valid")
        
        # Créer l'utilisateur
        user = User(
            email=data['email'],
            nom=data['nom'],
            prenom=data['prenom'],
            telephone=data.get('telephone'),
            adresse=data.get('adresse'),
            region=data.get('region'),
            type_utilisateur=UserType.Utilisateur
        )
        
        print(f"✅ User object created")
        
        try:
            user.set_password(data['password'])
            print(f"✅ Password set successfully")
        except ValueError as e:
            print(f"ERROR setting password: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return jsonify({'error': str(e)}), 400
        
        # Générer un token de vérification d'email
        verification_token = user.generate_verification_token()
        print(f"✅ Verification token generated: {verification_token[:20]}...")
        
        db.session.add(user)
        db.session.commit()
        print(f"✅ User saved to database, ID: {user.id}")
        
        # Logger l'action
        AuditLog.log_action(
            user_id=user.id,
            action='register',
            resource_type='user',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        print(f"✅ Audit log created")
        print(f"=== REGISTER SUCCESS ===")
        
        return jsonify({
            'message': 'Inscription réussie. Vérifiez votre email.',
            'verification_token': verification_token
        }), 201
        
    except Exception as e:
        print(f"\n❌ EXCEPTION in register: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        db.session.rollback()
        return jsonify({'error': 'Erreur lors de l\'inscription', 'details': str(e)}), 500

@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Vérification de l'email"""
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        return jsonify({'error': 'Token de vérification invalide'}), 400
    
    user.verify_email()
    db.session.commit()
    
    AuditLog.log_action(
        user_id=user.id,
        action='verify_email',
        resource_type='user',
        resource_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    return jsonify({'message': 'Email vérifié avec succès'}), 200

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """Connexion utilisateur"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email et mot de passe requis'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            return jsonify({'error': 'Identifiants invalides'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Compte désactivé'}), 403
        
        # Vérifier si le compte est verrouillé
        if user.compte_verrouille:
            if user.verrouillage_jusque and user.verrouillage_jusque > datetime.now(timezone.utc):
                return jsonify({
                    'error': f"Compte verrouillé jusqu'à {user.verrouillage_jusque.isoformat()}"
                }), 423
            elif user.verrouillage_jusque and user.verrouillage_jusque <= datetime.now(timezone.utc):
                user.compte_verrouille = False
                user.verrouillage_jusque = None
                db.session.commit()
        
        if not user.check_password(data['password']):
            AuditLog.log_action(
                user_id=user.id,
                action='login_failed',
                resource_type='user',
                resource_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False
            )
            return jsonify({'error': 'Identifiants invalides'}), 401
        
        # Créer les tokens JWT
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'type': user.type_utilisateur.value,
                'email': user.email
            }
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        # Logger la connexion réussie
        AuditLog.log_action(
            user_id=user.id,
            action='login_success',
            resource_type='user',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'message': 'Connexion réussie',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'nom': user.nom,
                'prenom': user.prenom,
                'type': user.type_utilisateur.value,
                'email_verified': user.email_verified,
                'telephone': user.telephone,
                'adresse': user.adresse
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Erreur lors de la connexion', 'details': str(e)}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Rafraîchir le token d'accès"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'Utilisateur non autorisé'}), 403
    
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            'type': user.type_utilisateur.value,
            'email': user.email
        }
    )
    
    return jsonify({'access_token': access_token}), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Déconnexion utilisateur"""
    jti = get_jwt()['jti']
    token_type = get_jwt()['type']
    user_id = get_jwt_identity()
    expires = datetime.fromtimestamp(get_jwt()['exp'])
    
    # Ajouter le token à la liste noire
    blacklist_token = TokenBlacklist(
        jti=jti,
        token_type=token_type,
        user_id=user_id,
        expires_at=expires
    )
    db.session.add(blacklist_token)
    db.session.commit()
    
    AuditLog.log_action(
        user_id=user_id,
        action='logout',
        resource_type='user',
        resource_id=user_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    return jsonify({'message': 'Déconnexion réussie'}), 200

@auth_bp.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Demande de réinitialisation de mot de passe"""
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'error': 'Email requis'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if user:
        reset_token = user.generate_reset_token()
        db.session.commit()
        
        AuditLog.log_action(
            user_id=user.id,
            action='password_reset_request',
            resource_type='user',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
    
    return jsonify({
        'message': 'Si cet email existe, un lien de réinitialisation a été envoyé'
    }), 200

@auth_bp.route('/reset-password', methods=['POST'])
@limiter.limit("3 per hour")
def reset_password():
    """Réinitialisation du mot de passe"""
    data = request.get_json()
    
    if not data or not data.get('token') or not data.get('new_password'):
        return jsonify({'error': 'Token et nouveau mot de passe requis'}), 400
    
    user = User.query.filter_by(reset_token=data['token']).first()
    
    if not user or not user.reset_token_expiry:
        return jsonify({'error': 'Token invalide ou expiré'}), 400
    
    if datetime.now(timezone.utc) > user.reset_token_expiry:
        return jsonify({'error': 'Token expiré'}), 400
    
    try:
        user.set_password(data['new_password'])
        user.reset_token = None
        user.reset_token_expiry = None
        user.reset_tentatives()
        db.session.commit()
        
        AuditLog.log_action(
            user_id=user.id,
            action='password_reset_success',
            resource_type='user',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'message': 'Mot de passe réinitialisé avec succès'}), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
# Supprimer le paramètre error non utilisé dans les gestionnaires d'erreur
@auth_bp.errorhandler(400)
def bad_request(_error):
    """Gestionnaire d'erreur 400"""
    return jsonify({'error': 'Requête invalide'}), 400

@auth_bp.errorhandler(401)
def unauthorized(_error):
    """Gestionnaire d'erreur 401"""
    return jsonify({'error': 'Non autorisé'}), 401

@auth_bp.errorhandler(403)
def forbidden(_error):
    """Gestionnaire d'erreur 403"""
    return jsonify({'error': 'Accès interdit'}), 403