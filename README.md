Olá, seja bem vindo ao meu programa de Brainstorm via Pyhon com o Framework Flask, onde são cadastrado erros de sistema e compartilhado entre os colegas.

#Banco de dados (SQLSERVER)
O banco de dados é SQLSERVER formado pelas tabelas: 
USUARIOS com as colunas: id,username,password,first_login(boolean)
CHAMADOS com as colunas: id,numero_chamado,nome_cliente,nome_modulo,descricao_erro,solucao	arquivo,usuario_inclusao

#Senhas:
*As senhas são crptografadas ao serem salvas no banco de dados.
*Ao fazer o primeiro login é solicitado a alteração de senha
*Após criar o primeiro usuário via banco, é necessário rodar o atualizar_senhas.py para que o sistema criptografe a senha atual e seja possível realizar o login na página

#Anexos:
Os anexos são salvos no /static/uploads/

Developed by Bruno Marques.
