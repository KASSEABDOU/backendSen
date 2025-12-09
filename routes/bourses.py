# routes/bourses.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

# routes/bourses.py
from models import db, Bourse, BourseStatus, TypeBourse, User, UserType, AuditLog
from utils.decorators import role_required
from datetime import datetime
import secrets
import string

bourses_bp = Blueprint('bourses', __name__)

@bourses_bp.route('bourses', methods=['GET'])
@jwt_required()
def get_bourses():
    """Liste des bourses disponibles"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Filtres
    status = request.args.get('status', BourseStatus.OUVERTE.value)
    type_bourse = request.args.get('type')
    annee = request.args.get('annee')
    
    query = Bourse.query
    
    # Appliquer les filtres
    if status:
        query = query.filter_by(status=BourseStatus(status))
    
    if type_bourse:
        query = query.filter_by(type_bourse=TypeBourse(type_bourse))
    
    if annee:
        query = query.filter_by(annee_academique=annee)
    
    bourses = query.all()
    
    return jsonify({
        'bourses': [{
            'id': b.id,
            'proprietaire':user.nom,
            'type_bourse': b.type_bourse.value,
            'annee_academique': b.annee_academique,
            'montant_demande': b.montant_demande,
            'montant_accorde': b.montant_accorde,
            'criteres_eligibilite': b.criteres_eligibilite,
            'pays_eligible': b.pays_eligible,
            'description': b.description,
            'status': b.status.value,
            'date_limite': b.date_limite.isoformat() if b.date_limite else None,
            'date_demande': b.date_demande.isoformat() if b.date_demande else None,
            'nombre_dossier': b.nombre_dossier,
            'lightblue': b.lightblue
        } for b in bourses]
    }), 200
    
def generate_bourse_code(type_bourse):
            """Générer un code unique basé sur le type de bourse"""
            prefix_map = {
                TypeBourse.MERITE: "MER",
                TypeBourse.SOCIALE: "SOC", 
                TypeBourse.EXCELLENCE: "EXC",
                TypeBourse.RECHERCHE: "RCH",
                TypeBourse.MOBILITE: "MOB"
            }
            prefix = prefix_map.get(type_bourse, "BRS")
            random_part = ''.join(secrets.choice(string.digits) for _ in range(6))
            return f"{prefix}_{random_part}"
        
        
@bourses_bp.route('/lightblue', methods=['GET'])
@jwt_required()
def get_unique_lightblue():
    """Récupérer toutes les valeurs uniques de lightblue"""
    try:
        # Méthode 1: Utiliser distinct()
        unique_lightblue = db.session.query(Bourse.lightblue).distinct().all()
        
        # Méthode 2: Ou utiliser group_by()
        # unique_lightblue = Bourse.query.with_entities(Bourse.lightblue).group_by(Bourse.lightblue).all()
        
        lightblue_list = [item[0] for item in unique_lightblue if item[0]]
        
        return jsonify({
            'lightblue_unique': lightblue_list
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Erreur lors de la récupération: {str(e)}'}), 500

@bourses_bp.route('/<int:bourse_id>', methods=['GET'])
@jwt_required()
def get_bourse(bourse_id):
    """Détails d'une bourse"""
    bourse = Bourse.query.get_or_404(bourse_id)
    
    return jsonify({
        'id': bourse.id,
        'type': bourse.type_bourse.value,
        'annee_academique': bourse.annee_academique,
        'montant_demande': bourse.montant_demande,
        'montant_accorde': bourse.montant_accorde,
        'description': bourse.description,
        'criteres_eligibilite': bourse.criteres_eligibilite,
        'status': bourse.status.value,
        'date_limite': bourse.date_limite.isoformat() if bourse.date_limite else None,
        'nombre_dossier': bourse.nombre_dossier,
        'pays_eligible': bourse.pays_eligible,
        'niveau_etude': bourse.niveau_etude,
        'domaine_etude': bourse.domaine_etude,
        'lightblue': bourse.lightblue
    }), 200

@bourses_bp.route('create', methods=['POST','OPTIONS'])
@role_required(UserType.ADMIN, UserType.Utilisateur)
def create_bourse():
    """Créer une nouvelle bourse"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validation
        required_fields = ['type_bourse', 'montant_demande', 'description']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Le champ {field} est requis'}), 400
        
        # Créer la bourse
        bourse = Bourse(
            user_id=user_id,
            type_bourse=TypeBourse(data['type_bourse']),
            montant_demande=data['montant_demande'],
            description=data['description'],
            date_demande=datetime.utcnow(),  # date automatique,
            annee_academique=data['annee_academique'],
            criteres_eligibilite=data['criteres_eligibilite'],
            pays_eligible=data.get('pays_eligible'),
            niveau_etude=data['niveau_etude'],
            status=data.get('status'),
            lightblue=generate_bourse_code(TypeBourse(data['type_bourse'])),
            domaine_etude=data['domaine_etude']
        )
        
        # Valider le montant
        try:
            bourse.validate_montant(data['montant_demande'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        db.session.add(bourse)
        db.session.commit()
        
        AuditLog.log_action(
            user_id=user_id,
            action='create_bourse',
            resource_type='bourse',
            resource_id=bourse.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'message': 'Bourse créée avec succès',
            'bourse_id': bourse.id,
            'nombre_dossier': bourse.nombre_dossier
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erreur lors de la création', 'details': str(e)}), 500
    


@bourses_bp.errorhandler(404)
def bourse_not_found(_error):
    """Gestionnaire d'erreur 404 spécifique aux bourses"""
    return jsonify({'error': 'Bourse non trouvée'}), 404

@bourses_bp.errorhandler(400)
def bad_request(_error):
    """Gestionnaire d'erreur 400"""
    return jsonify({'error': 'Données de requête invalides'}), 400