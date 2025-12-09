# create_admin.py
def create_default_admin(db, User, UserType):
    if User.query.filter_by(type_utilisateur=UserType.ADMIN).first():
        print("Admin par défaut déjà présent.")
        return
    
    admin = User(
        email='admin@example.com',
        nom='Admin',
        prenom='Super',
        type_utilisateur=UserType.ADMIN
    )
    admin.set_password('Admin@1234')
    db.session.add(admin)
    db.session.commit()
    print("Admin par défaut créé avec succès !")
