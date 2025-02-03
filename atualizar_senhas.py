from app import app, db, Usuario

with app.app_context():
    usuarios = Usuario.query.all()
    for usuario in usuarios:
        if not usuario.password.startswith('scrypt:'):  # Verifica se a senha já está criptografada
            usuario.set_password(usuario.password)  # Criptografa a senha
            db.session.commit()
            print(f"Senha do usuário {usuario.username} atualizada com sucesso.")