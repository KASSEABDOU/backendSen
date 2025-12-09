from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import sqlite3
from datetime import datetime

users_bp = Blueprint('users', __name__)

import sqlite3
import os
from pathlib import Path
from models import User,UserType

# Fonction pour connexion base de données CORRIGÉE
def get_db_connection():
    # Chemin vers la VRAIE base de données
    base_dir = Path(__file__).parent.parent  # Remonter d'un niveau depuis routes/
    db_path = base_dir / 'instance' / 'senbourses.db'
    
    #print(f"🔗 Connexion à: {db_path}")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# Route pour obtenir tous les utilisateurs (Admin seulement)
@users_bp.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        user_id = get_jwt_identity()
        
        user = User.query.get(user_id)  # ✅ renvoie un objet User SQLAlchemy

        # Vérifier si c’est un admin
        if not user or user.type_utilisateur != UserType.ADMIN:
            return jsonify({'error': 'Accès refusé : privilèges insuffisants'}), 403
        
        # Récupérer tous les utilisateurs
        conn = get_db_connection()
        users = conn.execute('''
            SELECT id, nom, prenom, email, telephone,type_utilisateur, date_creation, archive, is_active, adresse 
            FROM users 
            ORDER BY date_creation DESC
        ''').fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                "id": user['id'],
                "nom": user['nom'],
                "prenom": user['prenom'],
                "email": user['email'],
                "telephone": user['telephone'],
                "type_utilisateur": user['type_utilisateur'],
                "date_creation": user['date_creation'],
                "archive":user['archive'],
                "is_active":user['is_active'],
                "adresse": user['adresse']
            })
        
        return jsonify({"users": users_list, "count": len(users_list)}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour obtenir le profil de l'utilisateur connecté
@users_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        current_user_id = get_jwt_identity()
        
        conn = get_db_connection()
        user = conn.execute('''
            SELECT id, nom, prenom, email, telephone, adresse, date_creation, statut 
            FROM users 
            WHERE id = ?
        ''', (current_user_id,)).fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "Utilisateur non trouvé"}), 404
        
        user_profile = {
            "id": user['id'],
            "nom": user['nom'],
            "prenom": user['prenom'],
            "email": user['email'],
            "telephone": user['telephone'],
            "adresse": user['adresse'],
            "statut": user['statut']
        }
        
        return jsonify(user_profile), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour mettre à jour le profil utilisateur
@users_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        print(f"🟢 Mise à jour profil user_id: {current_user_id}")
        print(f"🟢 Données reçues: {data}")
        
        conn = get_db_connection()
        
        # Vérifier que l'utilisateur existe (avec les BONNES colonnes)
        existing_user = conn.execute(
            'SELECT id, nom, prenom FROM users WHERE id = ?', (current_user_id,)
        ).fetchone()
        
        print(f"🟢 Utilisateur trouvé: {existing_user}")
        
        if not existing_user:
            conn.close()
            return jsonify({"error": "Utilisateur non trouvé"}), 404
        
        # Mettre à jour les champs autorisés
        allowed_fields = ['nom', 'prenom', 'telephone']
        update_fields = []
        update_values = []
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = ?")
                update_values.append(data[field])
                print(f"🟢 Champ à mettre à jour: {field} = {data[field]}")
        
        if not update_fields:
            conn.close()
            return jsonify({"error": "Aucune donnée valide à mettre à jour"}), 400
        
        update_values.append(current_user_id)
        
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        print(f"🟢 Requête: {query}")
        print(f"🟢 Valeurs: {update_values}")
        
        conn.execute(query, update_values)
        conn.commit()
        
        # Récupérer l'utilisateur mis à jour (avec les BONNES colonnes)
        updated_user = conn.execute('''
            SELECT id, nom, prenom, email, telephone, adresse, type_utilisateur, date_creation
            FROM users 
            WHERE id = ?
        ''', (current_user_id,)).fetchone()
        conn.close()
        
        user_profile = {
            "id": updated_user['id'],
            "nom": updated_user['nom'],
            "prenom": updated_user['prenom'],
            "email": updated_user['email'],
            "telephone": updated_user['telephone'],
            "adresse": updated_user['adresse'],
            "type_utilisateur": updated_user['type_utilisateur'],  # Pas 'role'
            "date_creation": updated_user['date_creation']
        }
        
        return jsonify({
            "message": "Profil mis à jour avec succès",
            "user": user_profile
        }), 200
        
    except Exception as e:
        print(f"❌ ERREUR: {str(e)}")
        import traceback
        print(f"❌ TRACEBACK: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Route pour changer le statut d'un utilisateur (Admin seulement)
@users_bp.route('/users/<int:user_id>/status', methods=['PUT'])
@jwt_required()
def update_user_status():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Vérifier si l'utilisateur est admin
        conn = get_db_connection()
        current_user = conn.execute(
            'SELECT role FROM users WHERE id = ?', (current_user_id,)
        ).fetchone()
        
        if not current_user or current_user['role'] != 'admin':
            conn.close()
            return jsonify({"error": "Accès non autorisé"}), 403
        
        # Validation des données
        if not data or 'statut' not in data:
            conn.close()
            return jsonify({"error": "Statut manquant"}), 400
        
        new_status = data['statut']
        if new_status not in ['actif', 'inactif', 'suspendu']:
            conn.close()
            return jsonify({"error": "Statut invalide"}), 400
        
        # Mettre à jour le statut
        conn.execute(
            'UPDATE users SET statut = ? WHERE id = ?',
            (new_status, user_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            "message": f"Statut de l'utilisateur mis à jour: {new_status}",
            "user_id": user_id,
            "new_status": new_status
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour obtenir les statistiques des utilisateurs (Admin seulement)
@users_bp.route('/users/stats', methods=['GET'])
@jwt_required()
def get_users_stats():
    try:
        current_user_id = get_jwt_identity()
        
        # Vérifier si l'utilisateur est admin
        conn = get_db_connection()
        user = conn.execute(
            'SELECT role FROM users WHERE id = ?', (current_user_id,)
        ).fetchone()
        
        if not user or user['role'] != 'admin':
            conn.close()
            return jsonify({"error": "Accès non autorisé"}), 403
        
        # Récupérer les statistiques
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as user_count,
                SUM(CASE WHEN statut = 'actif' THEN 1 ELSE 0 END) as active_count,
                SUM(CASE WHEN statut = 'inactif' THEN 1 ELSE 0 END) as inactive_count,
                SUM(CASE WHEN statut = 'suspendu' THEN 1 ELSE 0 END) as suspended_count,
                DATE(date_creation) as creation_date,
                COUNT(*) as daily_registrations
            FROM users 
            GROUP BY DATE(date_creation)
            ORDER BY creation_date DESC
            LIMIT 30
        ''').fetchall()
        conn.close()
        
        stats_list = [dict(row) for row in stats]
        
        return jsonify({"stats": stats_list}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour rechercher des utilisateurs (Admin seulement)
@users_bp.route('/users/search', methods=['GET'])
@jwt_required()
def search_users():
    try:
        current_user_id = get_jwt_identity()
        search_term = request.args.get('q', '')
        
        if not search_term:
            return jsonify({"error": "Terme de recherche manquant"}), 400
        
        # Vérifier si l'utilisateur est admin
        conn = get_db_connection()
        user = conn.execute(
            'SELECT role FROM users WHERE id = ?', (current_user_id,)
        ).fetchone()
        
        if not user or user['role'] != 'admin':
            conn.close()
            return jsonify({"error": "Accès non autorisé"}), 403
        
        # Rechercher les utilisateurs
        users = conn.execute('''
            SELECT id, nom, prenom, email, telephone, role, date_creation, statut 
            FROM users 
            WHERE nom LIKE ? OR prenom LIKE ? OR email LIKE ?
            ORDER BY nom, prenom
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')).fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                "id": user['id'],
                "nom": user['nom'],
                "prenom": user['prenom'],
                "email": user['email'],
                "telephone": user['telephone'],
                "role": user['role'],
                "date_creation": user['date_creation'],
                "statut": user['statut']
            })
        
        return jsonify({
            "users": users_list,
            "count": len(users_list),
            "search_term": search_term
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500