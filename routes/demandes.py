# routes/demandes.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import db, Demande, Bourse, BourseStatus, TypeBourse, User, UserType, AuditLog, DemandeStatus
from utils.decorators import role_required

demandes_bp = Blueprint('demandes', __name__)

@demandes_bp.route('', methods=['GET'])
@jwt_required()
def get_demandes():
    """Liste des demandes de l'utilisateur"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Les admins voient toutes les demandes, les autres seulement les leurs
    if user.type_utilisateur == UserType.ADMIN:
        demandes = Demande.query.all()
    else:
        demandes = Demande.query.filter_by(user_id=user_id).all()
    
    return jsonify({
        'demandes': [d.to_dict() for d in demandes]
    }), 200

@demandes_bp.route('/<int:demande_id>', methods=['GET'])
@jwt_required()
def get_demande(demande_id):
    """Détails d'une demande"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    demande = Demande.query.get_or_404(demande_id)
    
    # Vérifier l'autorisation
    if user.type_utilisateur != UserType.Utilisateur and demande.user_id != user_id:
        return jsonify({'error': 'Accès non autorisé'}), 403
    
    return jsonify(demande.to_dict()), 200

@demandes_bp.route('create', methods=['POST'])
@jwt_required()
@role_required(UserType.Utilisateur)
def create_demande():
    """Créer une nouvelle demande de bourse"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validation
        required_fields = ['type_bourse', 'montant_demande']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Le champ {field} est requis'}), 400
            
         # Convertir la string en enum
        try:
            type_bourse_enum = data['type_bourse']
        except ValueError:
            return jsonify({'error': f'Type de bourse invalide: {data['type_bourse']}'}), 400
        
        bourse = Bourse.query.filter_by(type_bourse=TypeBourse(type_bourse_enum)).first()
        if not bourse:
          return jsonify({'error': f'Aucune bourse trouvée pour le type: {type_bourse_enum}'}), 404
        

        
        if bourse.status != BourseStatus.OUVERTE:
            return jsonify({'error': 'Cette bourse n\'est plus ouverte'}), 400
        
        # Créer la demande
        demande = Demande(
            user_id=user_id,
            bourse_id=bourse.id,
            type_bourse=TypeBourse(data['type_bourse']),
            niveau_etude=data.get('niveau_etude'),
            annee_academique=data.get('annee_academique'),
            montant_demande=data['montant_demande'],
            justification=data.get('justification'),
            description=data.get('description')
        )
        
        # Validation
        try:
            demande.validate_montant_demande(data['montant_demande'])
            if data.get('annee_academique'):
                demande.validate_annee_academique(data['annee_academique'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        db.session.add(demande)
        db.session.commit()
        
        AuditLog.log_action(
            user_id=user_id,
            action='create_demande',
            resource_type='demande',
            resource_id=demande.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'message': 'Demande créée avec succès',
            'demande_id': demande.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erreur lors de la création', 'details': str(e)}), 500
    
@demandes_bp.route('/demandeByUser/<int:user_id>', methods=['GET'])
@jwt_required()
def get_demandes_by_user(user_id):
    demandes = Demande.get_by_user(user_id)
    return jsonify([{
        "id": d.id,
        "type_bourse": d.type_bourse.value,
        "status": d.status.value,
        "montant_demande": d.montant_demande,
        "date_creation": d.date_creation,
    } for d in demandes]), 200


@demandes_bp.route('/<int:demande_id>/soumettre', methods=['POST'])
@jwt_required()
def soumettre_demande(demande_id):
    """Soumettre une demande pour évaluation"""
    user_id = get_jwt_identity()
    demande = Demande.query.get_or_404(demande_id)
    
    # Vérifier l'autorisation
    if str(demande.user_id) != user_id:
        return jsonify({'error': user_id}), 403
    
    try:
        demande.soumettre()
        db.session.commit()
        
        AuditLog.log_action(
            user_id=user_id,
            action='soumettre_demande',
            resource_type='demande',
            resource_id=demande.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'message': 'Demande soumise avec succès'}), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    

@demandes_bp.errorhandler(404)
def demande_not_found(_error):
    """Gestionnaire d'erreur 404 spécifique aux demandes"""
    return jsonify({'error': 'Demande non trouvée'}), 404

@demandes_bp.errorhandler(403)
def forbidden(_error):
    """Gestionnaire d'erreur 403"""
    return jsonify({'error': 'Accès non autorisé à cette demande'}), 403