from funcao import criptografar
from main import get_db_connection

con = get_db_connection()

if con is None:
    print("Erro ao conectar no banco")
    exit()

cur = con.cursor()

try:

    senha_hash = criptografar("Rayssa123@")

    cur.execute("""
        INSERT INTO usuario (
            nome, email, telefone, senha, id_cargo,
            conta_confirmada, bloqueado, tentativas_login
        )
        VALUES (?, ?, ?, ?, ?, 1, 0, 0)
    """, (
        "Rayssa",
        "andrade.rayssa.da.silva@gmail.com",
        "11985942256",
        senha_hash,
        2
    ))

    con.commit()

    print("ADMIN CRIADO COM SUCESSO")

except Exception as e:

    con.rollback()
    print("ERRO:", e)

finally:

    con.close()