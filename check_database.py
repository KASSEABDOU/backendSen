# check_database.py
import sqlite3
import os
from app import create_app, db
from models import User, Bourse

def check_database():
    print("🔍 Vérification de la base de données...")
    
    # Vérifier si le fichier existe
    db_path = 'sen_bourse.db'
    if os.path.exists(db_path):
        print(f"✅ Fichier de base de données trouvé: {db_path} ({os.path.getsize(db_path)} octets)")
    else:
        print(f"❌ Fichier de base de données NON trouvé: {db_path}")
        return
    
    # Vérifier avec SQLAlchemy
    app = create_app()
    with app.app_context():
        try:
            # Vérifier si la table users existe
            users_count = User.query.count()
            print(f"✅ Table 'users' existe avec {users_count} utilisateur(s)")
            
            bourse = Bourse.query.count()
            print(f"✅ Table 'Bourse' existe avec {bourse} utilisateur(s)")
            
            # Afficher les utilisateurs
            users = User.query.all()
            for user in users:
                print(f"   👤 {user.id}: {user.prenom} {user.nom} ({user.email}) {user.telephone} {user.adresse} {user.type_utilisateur.value}")
            
            bourses = Bourse.query.all()
            for bourse in bourses:
                print(f"   👤 {bourse.id}: {bourse.lightblue}")
                
            
                
                
        except Exception as e:
            print(f"❌ Erreur avec SQLAlchemy: {e}")
            print("🔄 Tentative de création des tables...")
            
            # Créer les tables
            db.create_all()
            print("✅ Tables créées")
            
            # Vérifier à nouveau
            users_count = User.query.count()
            print(f"👥 {users_count} utilisateur(s) après création")

def check_with_sqlite():
    """Vérification directe avec sqlite3"""
    print("\n🔍 Vérification directe SQLite...")
    try:
        conn = sqlite3.connect('sen_bourse.db')
        cursor = conn.cursor()
        
        # Vérifier les tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"📦 Tables dans la base: {len(tables)}")
        for table in tables:
            print(f"   - {table[0]}")
            
            # Afficher le contenu de la table users
            if table[0] == 'users':
                cursor.execute("SELECT * FROM users")
                users = cursor.fetchall()
                print(f"     👥 Contenu: {len(users)} ligne(s)")
                for user in users:
                    print(f"       {user}")
                    
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erreur vérification SQLite: {e}")

if __name__ == '__main__':
    check_database()
    check_with_sqlite()