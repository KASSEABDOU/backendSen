from flask import Blueprint

documents_bp = Blueprint('documents', __name__)

# Vos routes ici
@documents_bp.route('/documents')
def get_documents():
    return "Documents endpoint"