"""
Modèles SQLAlchemy pour la plateforme SenBourses
Système de gestion des bourses d'études
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from enum import Enum
import re
import secrets
import string

db = SQLAlchemy()

class UserType(Enum):
    """Types d'utilisateurs"""
    Utilisateur = "USERS"
    Gestionnaire = "GESTION"
    ADMIN = "ADMIN"

class DemandeStatus(Enum):
    """Statuts des demandes de bourse"""
    BROUILLON = "brouillon"
    SOUMISE = "soumise"
    EN_COURS = "en_cours"
    APPROUVEE = "approuvee"
    REJETEE = "rejetee"
    EN_ATTENTE = "en_attente"

class BourseStatus(Enum):
    """Statuts des bourses"""
    OUVERTE = "ouverte"
    FERMEE = "fermee"
    ARCHIVEE = "archivee"

class TypeBourse(Enum):
    """Types de bourses"""
    MERITE = "merite"
    SOCIALE = "sociale"
    EXCELLENCE = "excellence"
    RECHERCHE = "recherche"
    MOBILITE = "mobilite"

class User(UserMixin, db.Model):
    """Modèle utilisateur avec authentification sécurisée"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    telephone = db.Column(db.String(20))
    adresse = db.Column(db.String(255))
    region = db.Column(db.String(100))
    type_utilisateur = db.Column(db.Enum(UserType), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    archive = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    # NOUVEAU : Photo de profil
    photo_url = db.Column(db.String(500), default='assets/images/avatar.jpg')
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_derniere_connexion = db.Column(db.DateTime)
    tentatives_connexion = db.Column(db.Integer, default=0)
    compte_verrouille = db.Column(db.Boolean, default=False)
    verrouillage_jusque = db.Column(db.DateTime)
    
    # Relations
    demandes = db.relationship('Demande', backref='utilisateur', lazy='dynamic', 
                               cascade='all, delete-orphan')
    reclamations = db.relationship('Reclamation', backref='utilisateur', lazy='dynamic',
                                  foreign_keys='Reclamation.user_id')
    
    def set_password(self, password):
        """Hash et stocke le mot de passe avec validation"""
        if not self.validate_password(password):
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères, "
                           "une majuscule, une minuscule, un chiffre et un caractère spécial")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Vérifie le mot de passe et gère les tentatives"""
        if self.compte_verrouille and self.verrouillage_jusque:
            if datetime.utcnow() < self.verrouillage_jusque:
                return False
            else:
                # Déverrouiller le compte
                self.compte_verrouille = False
                self.verrouillage_jusque = None
                self.tentatives_connexion = 0
        
        is_correct = check_password_hash(self.password_hash, password)
        
        if not is_correct:
            self.increment_tentatives()
        else:
            self.reset_tentatives()
            self.date_derniere_connexion = datetime.utcnow()
        
        db.session.commit()
        return is_correct
    
    def increment_tentatives(self):
        """Incrémente les tentatives de connexion et verrouille si nécessaire"""
        self.tentatives_connexion += 1
        if self.tentatives_connexion >= 5:
            from datetime import timedelta
            self.compte_verrouille = True
            self.verrouillage_jusque = datetime.utcnow() + timedelta(minutes=30)
    
    def reset_tentatives(self):
        """Réinitialise les tentatives de connexion"""
        self.tentatives_connexion = 0
        self.compte_verrouille = False
        self.verrouillage_jusque = None
    
    @staticmethod
    def validate_email(email):
        """Valide le format de l'email (RFC 5322)"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_telephone(telephone):
        """Valide le format du téléphone sénégalais"""
        pattern = r'^(\+221|00221)?[0-9]{9}$'
        return re.match(pattern, telephone) is not None
    
    @staticmethod
    def validate_password(password):
        """Valide la force du mot de passe"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    def generate_verification_token(self):
        """Génère un token de vérification d'email"""
        self.verification_token = secrets.token_urlsafe(32)
        return self.verification_token
    
    def generate_reset_token(self):
        """Génère un token de réinitialisation de mot de passe"""
        from datetime import timedelta
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=24)
        return self.reset_token
    
    def verify_email(self):
        """Marque l'email comme vérifié"""
        self.email_verified = True
        self.verification_token = None
    
    @property
    def full_name(self):
        """Nom complet de l'utilisateur"""
        return f"{self.prenom} {self.nom}"
    
    def __repr__(self):
        return f'<User {self.email}>'

class Bourse(db.Model):
    """Modèle des bourses d'études"""
    __tablename__ = 'bourses'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    lightblue = db.Column(db.String(100),nullable=False, unique=True)  # Identifiant métier
    type_bourse = db.Column(db.Enum(TypeBourse), nullable=False, unique=True)
    annee_academique = db.Column(db.String(20), nullable=False)
    montant_demande = db.Column(db.Float, nullable=False)
    montant_accorde = db.Column(db.Float)
    description = db.Column(db.Text)
    criteres_eligibilite = db.Column(db.Text)
    status = db.Column(db.Enum(BourseStatus), default=BourseStatus.OUVERTE)
    date_demande = db.Column(db.DateTime, default=datetime.utcnow)
    date_traitement = db.Column(db.DateTime)
    motif_rejet = db.Column(db.Text)
    
    # Métadonnées
    nombre_dossier = db.Column(db.String(50), unique=True)
    date_limite = db.Column(db.DateTime)
    pays_eligible = db.Column(db.String(255))  # Liste séparée par virgules
    niveau_etude = db.Column(db.String(100))
    domaine_etude = db.Column(db.String(255))
    
    # Relations
    createur = db.relationship('User', backref='bourses_creees')
    demandes = db.relationship('Demande', backref='bourse', lazy='dynamic',
                              cascade='all, delete-orphan')
    
    def __init__(self, **kwargs):
        super(Bourse, self).__init__(**kwargs)
        self.generate_numero_dossier()
    
    def generate_numero_dossier(self):
        """Génère un numéro de dossier unique"""
        import random
        annee = datetime.now().year
        random_part = random.randint(10000, 99999)
        self.nombre_dossier = f"SB{annee}{random_part}"
    
    def validate_montant(self, montant):
        """Valide le montant de la bourse"""
        # Contrainte: Montant entre 500,000 et 5,000,000 FCFA
        if montant < 500000 or montant > 5000000:
            raise ValueError("Le montant doit être entre 500,000 et 5,000,000 FCFA")
        return True
    
    def is_eligible_for_user(self, user):
        """Vérifie si un utilisateur est éligible pour cette bourse"""
        # À implémenter selon les critères spécifiques
        return True
    
    def close_bourse(self):
        """Ferme la bourse"""
        self.status = BourseStatus.FERMEE
        self.date_traitement = datetime.utcnow()
    
    def __repr__(self):
        return f'<Bourse {self.nombre_dossier}>'

class Demande(db.Model):
    """Modèle des demandes de bourse"""
    __tablename__ = 'demandes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bourse_id = db.Column(db.Integer, db.ForeignKey('bourses.id'), nullable=False)
    lightblue = db.Column(db.String(100))
    type_bourse = db.Column(db.Enum(TypeBourse), nullable=False)
    niveau_etude = db.Column(db.String(100))
    annee_academique = db.Column(db.String(20))
    montant_demande = db.Column(db.Float, nullable=False)
    justification = db.Column(db.Text)
    description = db.Column(db.Text)
    status = db.Column(db.Enum(DemandeStatus), default=DemandeStatus.BROUILLON)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_modification = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    date_soumission = db.Column(db.DateTime)
    motif_rejet = db.Column(db.Text)
    
    # Score d'évaluation
    score_academique = db.Column(db.Float)
    score_social = db.Column(db.Float)
    score_final = db.Column(db.Float)
    
    # Relations
    documents = db.relationship('Document', backref='demande', lazy='dynamic',
                               cascade='all, delete-orphan')
    reclamations = db.relationship('Reclamation', backref='demande', lazy='dynamic',
                                  cascade='all, delete-orphan')
    
    def validate_type_bourse(self, type_bourse):
        """Valide le type de bourse"""
        return isinstance(type_bourse, TypeBourse)
    
    def validate_status(self, status):
        """Valide le statut"""
        return isinstance(status, DemandeStatus)
    
    def validate_montant_demande(self, montant):
        """Valide le montant demandé"""
        if montant <= 0:
            raise ValueError("Le montant doit être positif")
        if montant > 5000000:
            raise ValueError("Le montant ne peut pas dépasser 5,000,000 FCFA")
        return True
    
    def validate_montant_accorde(self, montant):
        """Valide le montant accordé"""
        if montant < 0:
            raise ValueError("Le montant accordé ne peut pas être négatif")
        if montant > self.montant_demande:
            raise ValueError("Le montant accordé ne peut pas dépasser le montant demandé")
        return True
    
    def validate_annee_academique(self, annee):
        """Valide l'année académique (format: YYYY-YYYY)"""
        pattern = r'^\d{4}-\d{4}$'
        if not re.match(pattern, annee):
            raise ValueError("Format d'année académique invalide (attendu: YYYY-YYYY)")
        return True
    
    def soumettre(self):
        """Soumet la demande pour évaluation"""
        if self.status != DemandeStatus.BROUILLON:
            raise ValueError("Seules les demandes en brouillon peuvent être soumises")
        
        # Vérifier que tous les documents requis sont présents
        #if not self.has_all_required_documents():
            #raise ValueError("Tous les documents requis doivent être fournis")
        
        self.status = DemandeStatus.SOUMISE
        self.date_soumission = datetime.utcnow()
    
    def has_all_required_documents(self):
        """Vérifie si tous les documents requis sont présents"""
        required_types = ['bulletin', 'certificat_scolarite', 'acte_naissance']
        uploaded_types = [doc.type for doc in self.documents.all()]
        return all(req_type in uploaded_types for req_type in required_types)
    
    def calculer_score(self):
        """Calcule le score final de la demande"""
        # Logique de calcul du score
        if self.score_academique and self.score_social:
            self.score_final = (self.score_academique * 0.6) + (self.score_social * 0.4)
    
    def to_dict(self):
        """Convertit en dictionnaire"""
        return {
            'id': self.id,
            'type_bourse': self.type_bourse.value,
            'montant_demande': self.montant_demande,
            'status': self.status.value,
            'date_creation': self.date_creation.isoformat(),
            'date_soumission': self.date_soumission.isoformat() if self.date_soumission else None,
            'score_final': self.score_final
        }
        
    @staticmethod
    def get_by_user(user_id):
        return Demande.query.filter_by(user_id=user_id).order_by(Demande.date_creation.desc()).all()
    
    def __repr__(self):
        return f'<Demande {self.id} - {self.status.value}>'

class Document(db.Model):
    """Modèle des documents joints aux demandes"""
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    demande_id = db.Column(db.Integer, db.ForeignKey('demandes.id'), nullable=False)
    nom = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(100), nullable=False)  # bulletin, certificat, acte_naissance, etc.
    url = db.Column(db.String(500), nullable=False)
    taille = db.Column(db.Integer)  # Taille en octets
    mime_type = db.Column(db.String(100))
    date_upload = db.Column(db.DateTime, default=datetime.utcnow)
    hash_fichier = db.Column(db.String(64))  # SHA-256 pour vérifier l'intégrité
    is_verified = db.Column(db.Boolean, default=False)
    
    # Métadonnées de sécurité
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45))
    
    def validate_taille(self, taille):
        """Valide la taille du document (max 10MB)"""
        MAX_SIZE = 10 * 1024 * 1024  # 10 MB
        if taille > MAX_SIZE:
            raise ValueError("La taille du document ne peut pas dépasser 10 MB")
        return True
    
    def validate_type(self, type_doc):
        """Valide le type de document"""
        valid_types = [
            'bulletin', 'certificat_scolarite', 'acte_naissance',
            'composition_familiale', 'permis_conduire', 'carte_identite',
            'releve_notes', 'lettre_motivation', 'cv', 'recommandation'
        ]
        if type_doc not in valid_types:
            raise ValueError(f"Type de document invalide. Types valides: {', '.join(valid_types)}")
        return True
    
    @staticmethod
    def calculate_hash(file_path):
        """Calcule le hash SHA-256 d'un fichier"""
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def __repr__(self):
        return f'<Document {self.nom}>'

class Reclamation(db.Model):
    """Modèle des réclamations"""
    __tablename__ = 'reclamations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bourse_id = db.Column(db.Integer, db.ForeignKey('bourses.id'))
    demande_id = db.Column(db.Integer, db.ForeignKey('demandes.id'))
    sujet = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='en_attente')
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_reponse = db.Column(db.DateTime)
    reponse_admin = db.Column(db.Text)
    priorite = db.Column(db.String(20), default='normale')  # basse, normale, haute, urgente
    
    # Relations
    bourse = db.relationship('Bourse', backref='reclamations')
    
    def __repr__(self):
        return f'<Reclamation {self.id} - {self.sujet}>'

class TokenBlacklist(db.Model):
    """Liste noire des tokens JWT révoqués"""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
    token_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        """Vérifie si un token est dans la liste noire"""
        query = cls.query.filter_by(jti=jti).first()
        return query is not None
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'

class AuditLog(db.Model):
    """Journal d'audit pour la traçabilité"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=True)
    
    @classmethod
    def log_action(cls, user_id, action, resource_type=None, resource_id=None,
                   details=None, ip_address=None, user_agent=None, success=True):
        """Enregistre une action dans le journal d'audit"""
        log_entry = cls(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry
    
    def __repr__(self):
        return f'<AuditLog {self.id} - {self.action}>'

# Fonctions utilitaires
def init_database(app):
    """Initialise la base de données"""
    with app.app_context():
        db.create_all()
        print("✅ Base de données initialisée")