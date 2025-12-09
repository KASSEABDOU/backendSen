# find_database.py
import os
import sqlite3
from pathlib import Path

def find_database_files():
    print("🔍 Recherche des fichiers de base de données...")
    
    # Chercher dans tout le projet
    project_root = Path(__file__).parent
    db_files = list(project_root.rglob("*.db"))
    db_files.extend(project_root.rglob("*.sqlite"))
    db_files.extend(project_root.rglob("*.sqlite3"))
    
    print(f"📁 Fichiers de base trouvés: {len(db_files)}")
    
    for db_file in db_files:
        print(f"\n📄 {db_file}")
        print(f"   📏 Taille: {db_file.stat().st_size} octets")
        print(f"   📍 Chemin: {db_file.absolute()}")
        
        # Essayer de lire les tables
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"   📦 Tables: {len(tables)}")
            for table in tables:
                print(f"      - {table[0]}")
            conn.close()
        except Exception as e:
            print(f"   ❌ Erreur lecture: {e}")

if __name__ == '__main__':
    find_database_files()