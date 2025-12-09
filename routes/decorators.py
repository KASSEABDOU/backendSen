# utils/decorators.py
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_limiter import Limiter

from models import User, UserType

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or not user.is_active:
                return jsonify({'error': 'Utilisateur non autorisé'}), 403
            
            if user.type_utilisateur not in roles:
                return jsonify({'error': 'Accès interdit'}), 403
            
            return fn(*args, **kwargs)
        return decorator
    return wrapper