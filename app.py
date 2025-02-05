from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import zipfile
import io

app = Flask(__name__)

# Configurações
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://CNP:ninguemsabe@MTZNOFS057760/sistema_chamados?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Sessão expira após 30 minutos
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de 16 MB para uploads

# Inicializa o banco de dados e o gerenciador de login
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuário
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_login = db.Column(db.Boolean, default=True)  # Campo para verificar o primeiro login

    def set_password(self, password):
        # Gera um hash da senha e armazena no campo password
        self.password = generate_password_hash(password)

    def check_password(self, password):
        # Verifica se a senha fornecida corresponde ao hash armazenado
        return check_password_hash(self.password, password)

# Modelo de Chamado
class Chamado(db.Model):
    __tablename__ = 'chamados'
    id = db.Column(db.Integer, primary_key=True)
    numero_chamado = db.Column(db.Integer, nullable=False)
    nome_cliente = db.Column(db.String(80), nullable=False)
    nome_modulo = db.Column(db.String(80), nullable=False)
    descricao_erro = db.Column(db.String(500), nullable=False)
    solucao = db.Column(db.String(500))
    arquivo = db.Column(db.String(120))
    usuario_inclusao = db.Column(db.String(80), nullable=False)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)


# Carrega o usuário para o Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Configura a sessão como não permanente
@app.before_request
def before_request():
    session.permanent = False

# Rota principal (redireciona para o login)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('listar_chamados'))  # Redireciona para a lista de chamados se o usuário estiver autenticado
    else:
        return redirect(url_for('login'))  # Redireciona para o login se o usuário não estiver autenticado

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Usuario.query.filter_by(username=username).first()
        if user and user.check_password(password):  # Verifica a senha criptografada
            login_user(user)
            if user.first_login:  # Verifica se é o primeiro login
                return redirect(url_for('alterar_senha'))  # Redireciona para a página de alteração de senha
            else:
                return redirect(url_for('listar_chamados'))
        else:
            flash('Login inválido', 'error')
    return render_template('login.html')

# Rota de Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rota para alteração de senha (primeiro login ou mudança de senha)
@app.route('/alterar_senha', methods=['GET', 'POST'])
@login_required
def alterar_senha():
    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem', 'error')
            return redirect(url_for('alterar_senha'))

        # Criptografa e atualiza a senha do usuário
        current_user.set_password(nova_senha)
        current_user.first_login = False  # Define como False (será salvo como 0 no banco de dados)
        db.session.commit()

        flash('Senha alterada com sucesso', 'success')
        return redirect(url_for('listar_chamados'))

    return render_template('alterar_senha.html')

# Rota para listar chamados
@app.route('/chamados')
@login_required
def listar_chamados():
    termo_pesquisa = request.args.get('q', '').strip()  # Obtém o termo de pesquisa da URL
    if termo_pesquisa:
        # Filtra os chamados que contêm o termo de pesquisa no número, descrição ou solução
        chamados = Chamado.query.filter(
            (Chamado.numero_chamado.contains(termo_pesquisa)) |
            (Chamado.descricao_erro.contains(termo_pesquisa)) |
            (Chamado.nome_cliente.contains(termo_pesquisa)) |
            (Chamado.solucao.contains(termo_pesquisa))
        ).all()
    else:
        # Se não houver termo de pesquisa, lista todos os chamados
        chamados = Chamado.query.all()
    return render_template('index.html', chamados=chamados, termo_pesquisa=termo_pesquisa)

# Rota para criar um novo chamado
@app.route('/criar_chamado', methods=['GET', 'POST'])
@login_required
def criar_chamado():
    if request.method == 'POST':
        nome_cliente = request.form['nome_cliente']
        nome_modulo = request.form['nome_modulo']
        descricao_erro = request.form['descricao_erro']
        solucao = request.form['solucao']

        # Processar arquivos anexados
        arquivos = request.files.getlist('arquivos')
        nomes_arquivos = []
        for arquivo in arquivos:
            if arquivo.filename != '':
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{arquivo.filename}"
                arquivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                nomes_arquivos.append(filename)

        # Obter o próximo número de chamado
        proximo_numero = db.session.query(db.func.max(Chamado.numero_chamado)).scalar() or 0
        proximo_numero += 1

        # Criar novo chamado
        novo_chamado = Chamado(
            numero_chamado=proximo_numero,
            nome_cliente=nome_cliente,
            nome_modulo=nome_modulo,
            descricao_erro=descricao_erro,
            solucao=solucao,
            arquivo=", ".join(nomes_arquivos) if nomes_arquivos else None,
            usuario_inclusao=current_user.username,
            data_cadastro = datetime.utcnow()
        )
        db.session.add(novo_chamado)
        db.session.commit()

        return redirect(url_for('listar_chamados'))

    return render_template('criar_chamado.html')

# Rota para visualizar um chamado específico
@app.route('/chamado/<int:numero_chamado>')
@login_required
def visualizar_chamado(numero_chamado):
    chamado = Chamado.query.filter_by(numero_chamado=numero_chamado).first()
    if chamado:
        return render_template('chamado.html', chamado=chamado)
    return "Chamado não encontrado", 404

# Rota para editar um chamado
@app.route('/editar_chamado/<int:numero_chamado>', methods=['GET', 'POST'])
@login_required
def editar_chamado(numero_chamado):
    chamado = Chamado.query.filter_by(numero_chamado=numero_chamado).first()
    if not chamado:
        flash('Chamado não encontrado', 'error')
        return redirect(url_for('listar_chamados'))

    # Verificar se o usuário tem permissão para editar (somente o usuário que criou pode editar)
    if chamado.usuario_inclusao != current_user.username:
        flash('Você não tem permissão para editar este chamado', 'error')
        return redirect(url_for('listar_chamados'))

    if request.method == 'POST':
        chamado.nome_cliente = request.form['nome_cliente']
        chamado.nome_modulo = request.form['nome_modulo']
        chamado.descricao_erro = request.form['descricao_erro']
        chamado.solucao = request.form['solucao']

        # Processar novos arquivos anexados
        arquivos = request.files.getlist('arquivos')
        nomes_arquivos = []
        for arquivo in arquivos:
            if arquivo.filename != '':
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{arquivo.filename}"
                arquivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                nomes_arquivos.append(filename)

        if nomes_arquivos:
            chamado.arquivo = ", ".join(nomes_arquivos)

        db.session.commit()
        flash('Chamado atualizado com sucesso', 'success')
        return redirect(url_for('visualizar_chamado', numero_chamado=chamado.numero_chamado))

    return render_template('editar_chamado.html', chamado=chamado)

# Rota para baixar anexos como .zip
@app.route('/baixar_anexos/<int:numero_chamado>')
@login_required
def baixar_anexos(numero_chamado):
    chamado = Chamado.query.filter_by(numero_chamado=numero_chamado).first()
    if not chamado or not chamado.arquivo:
        flash("Nenhum anexo disponível para download.", "error")
        return redirect(url_for('visualizar_chamado', numero_chamado=numero_chamado))

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for arquivo_nome in chamado.arquivo.split(', '):
            arquivo_path = os.path.join(app.config['UPLOAD_FOLDER'], arquivo_nome)
            if os.path.exists(arquivo_path):
                zip_file.write(arquivo_path, arquivo_nome)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"chamado_{numero_chamado}_anexos.zip"
    )

# Rota para servir arquivos estáticos (uploads)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Inicializa o banco de dados e cria a pasta de uploads
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5000)
