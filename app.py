# app.py
"""
Application Flask sécurisée pour la plateforme SenBourses
Gestion des bourses d'études avec authentification JWT
"""

from flask import Flask,jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, request, make_response
import os
from datetime import timedelta
from models import User, UserType


from models import db, init_database
from create_admin import create_default_admin
from pathlib import Path

def create_app():
    """Factory pour créer l'application Flask"""
    app = Flask(__name__)
    
     # Chemin ABSOLU vers la VRAIE base de données
    base_dir = Path(__file__).parent
    db_path = base_dir / 'instance' / 'senbourses.db'
    
    # S'assurer que le dossier instance existe
    db_path.parent.mkdir(exist_ok=True)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///senbourses.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Configuration JWT
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or os.urandom(32)
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    
    # Configuration upload
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
    
    # Configuration du limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    
    # Rendre le limiter disponible globalement
    app.limiter = limiter
    
    # CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": os.environ.get('ALLOWED_ORIGINS', 'http://localhost:4200').split(','),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })
    @app.before_request
    def handle_options():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
            response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
            response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            return response
    
    # Initialisation des extensions
    db.init_app(app)
    jwt = JWTManager(app)
    
    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    
    # Import et enregistrement des blueprints
    from routes.auth import auth_bp
    from routes.bourses import bourses_bp
    from routes.demandes import demandes_bp
    from routes.documents import documents_bp
    from routes.reclamations import reclamations_bp
    from routes.users import users_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(bourses_bp, url_prefix='/api/bourses')
    app.register_blueprint(demandes_bp, url_prefix='/api/demandes')
    app.register_blueprint(documents_bp, url_prefix='/api/documents')
    app.register_blueprint(reclamations_bp, url_prefix='/api/reclamations')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    
    # Callback JWT
    from models import TokenBlacklist
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return TokenBlacklist.is_jti_blacklisted(jti)
    
    # Middleware de sécurité
    from middleware.security import add_security_headers
    app.after_request(add_security_headers)
    
    # Routes globales
    from datetime import datetime, timezone
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    
    # Gestion des erreurs
    from utils.error_handlers import register_error_handlers
    register_error_handlers(app)
    
    return app

    # Gestion des erreurs - version corrigée
    @app.errorhandler(404)
    def not_found_handler(_error):
        """Gestionnaire d'erreur 404 global"""
        return jsonify({'error': 'Ressource introuvable'}), 404

    @app.errorhandler(500)
    def internal_error_handler(_error):
        """Gestionnaire d'erreur 500 global"""
        db.session.rollback()
        return jsonify({'error': 'Erreur interne du serveur'}), 500

    @app.errorhandler(429)
    def ratelimit_handler(_error):
        """Gestionnaire de limite de taux"""
        return jsonify({'error': 'Trop de requêtes. Veuillez réessayer plus tard.'}), 429

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        init_database(app)
        create_default_admin(db, User, UserType)
    
    app.run(host='0.0.0.0', port=5000, debug=False)