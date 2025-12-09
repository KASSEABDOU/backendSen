# utils/error_handlers.py
from flask import jsonify

def register_error_handlers(app):
    """
    Enregistre tous les gestionnaires d'erreurs pour l'application
    """
    
    @app.errorhandler(400)
    def bad_request(_error):
        """Requête malformée"""
        return jsonify({
            'error': 'Requête invalide',
            'message': 'Les données fournies sont incorrectes ou incomplètes'
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(_error):
        """Non authentifié"""
        return jsonify({
            'error': 'Non autorisé',
            'message': 'Authentification requise pour accéder à cette ressource'
        }), 401
    
    @app.errorhandler(403)
    def forbidden(_error):
        """Accès refusé"""
        return jsonify({
            'error': 'Accès interdit',
            'message': 'Vous n\'avez pas les permissions nécessaires'
        }), 403
    
    @app.errorhandler(404)
    def not_found(_error):
        """Ressource non trouvée"""
        return jsonify({
            'error': 'Ressource introuvable',
            'message': 'La ressource demandée n\'existe pas'
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(_error):
        """Méthode non autorisée"""
        return jsonify({
            'error': 'Méthode non autorisée',
            'message': 'Cette méthode HTTP n\'est pas supportée pour cette ressource'
        }), 405
    
    @app.errorhandler(409)
    def conflict(_error):
        """Conflit de données"""
        return jsonify({
            'error': 'Conflit',
            'message': 'Les données entrent en conflit avec des données existantes'
        }), 409
    
    @app.errorhandler(422)
    def unprocessable_entity(_error):
        """Données non traitables"""
        return jsonify({
            'error': 'Entité non traitable',
            'message': 'Les données fournies sont sémantiquement incorrectes'
        }), 422
    
    @app.errorhandler(429)
    def too_many_requests(_error):
        """Trop de requêtes"""
        return jsonify({
            'error': 'Trop de requêtes',
            'message': 'Vous avez dépassé la limite de requêtes autorisée'
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(_error):
        """Erreur interne du serveur"""
        return jsonify({
            'error': 'Erreur interne du serveur',
            'message': 'Une erreur interne s\'est produite. Veuillez réessayer plus tard.'
        }), 500
    
    @app.errorhandler(503)
    def service_unavailable(_error):
        """Service indisponible"""
        return jsonify({
            'error': 'Service indisponible',
            'message': 'Le service est temporairement indisponible. Veuillez réessayer plus tard.'
        }), 503