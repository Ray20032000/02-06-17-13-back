import re
import jwt
import datetime
import smtplib
import random
import string
import secrets
import os
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash



def verificar_senha(senha):

    if len(senha) < 8:
        return "A senha deve ter no mínimo 8 caracteres."
    if not re.search(r"[A-Z]", senha):
        return "A senha precisa de pelo menos uma letra maiúscula."
    if not re.search(r"[0-9]", senha):
        return "A senha precisa de pelo menos um número."
    if not re.search(r"[@$!%*?&]", senha):
        return "A senha precisa de um caractere especial (@$!%*?&)."
    return None


def criptografar(senha):

    return generate_password_hash(senha)


def checar_senha(senha_digitada, senha_hash):

    if not senha_hash:
        return False
    return check_password_hash(senha_hash, senha_digitada)


def verificar_reuso_senha(id_usuario, nova_senha, cursor):

    cursor.execute("""
        SELECT FIRST 3 senha_antiga
        FROM historico_senhas
        WHERE id_usuario = ?
        ORDER BY data_troca DESC 
    """, (id_usuario,))

    historico = cursor.fetchall()
    for registro in historico:

        if checar_senha(nova_senha, registro[0]):
            return True
    return False


def gerar_codigo():

    return f"{secrets.randbelow(1000000):06d}"


def enviando_email(destinatario, assunto, corpo_texto):
    try:
        email_origem = "andrade.rayssa.da.silva@gmail.com"
        senha_aplicativo = "oxiegyiahpuchxaw"

        smtp = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10)
        smtp.login(email_origem, senha_aplicativo)

        msg = EmailMessage()
        msg["Subject"] = assunto
        msg["From"] = email_origem
        msg["To"] = destinatario
        msg.set_content(corpo_texto)

        smtp.send_message(msg)
        smtp.quit()

        return True

    except Exception as e:
        print("Erro de email:", repr(e))
        return False

def gerar_token(id_usuario):
    from main import app
    payload = {
        "id": id_usuario,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")


def remover_bearer(token):
    if token and token.startswith("Bearer "):
        return token.split(" ")[1]
    return token


import re

def validar_complexidade_senha(senha):

    if len(senha) < 8:
        return False
    if not any(char.isalpha() for char in senha):
        return False
    if not any(char.isdigit() for char in senha):
        return False
    return True