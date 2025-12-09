from flask import Blueprint, request, jsonify
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

# routes/bourses.py
from models import db, Reclamation, User, Bourse, AuditLog, UserType
from utils.decorators import role_required
from datetime import datetime


reclamations_bp = Blueprint('reclamations', __name__)

@reclamations_bp.route('/reclamations', methods=['GET'])
def get_reclamations():
    return jsonify({"message": "Endpoint des réclamations"})

@reclamations_bp.route('/create', methods=['POST'])
@jwt_required()
def create_reclamation():
    """Créer une nouvelle réclamation"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validation des champs requis
        required_fields = [ 'sujet', 'message']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Champ manquant: {field}'}), 400
        
        # Vérifier que l'utilisateur existe
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        
        # Vérifier que la bourse existe
        bourse = Bourse.query.get(data['type'])
        if not bourse:
            return jsonify({'error': data.get('type')}), 404
        
        # Vérifier que l'utilisateur a le droit de créer une réclamation pour cette bourse
        # (optionnel: vérifier si l'utilisateur est propriétaire de la bourse)
       # if bourse.user_id != user_id and user.type != UserType.ADMIN:
            #return jsonify({'error': 'Non autorisé à créer une réclamation pour cette bourse'}), 403
        
        # Créer la réclamation
        nouvelle_reclamation = Reclamation(
            user_id=user_id,
            bourse_id=bourse.id,
            sujet=data['sujet'],
            description=data['description'],
            statut='en_attente',
            date_creation=datetime.utcnow()
        )
        
        db.session.add(nouvelle_reclamation)
        db.session.commit()
        
        # Log d'audit
        audit_log = AuditLog(
            user_id=user_id,
            action='CREATE_RECLAMATION',
            description=f'Création réclamation #{nouvelle_reclamation.id} pour bourse #{bourse.id}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Réclamation créée avec succès',
            'reclamation': {
                'id': nouvelle_reclamation.id,
                'sujet': nouvelle_reclamation.sujet,
                'statut': nouvelle_reclamation.status,
                'date_creation': nouvelle_reclamation.date_creation.isoformat(),
                'bourse_id': nouvelle_reclamation.bourse_id,
                'user_id': nouvelle_reclamation.user_id
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erreur lors de la création de la réclamation: {str(e)}'}), 500