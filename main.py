import fdb
from flask import Flask
from flask_cors import CORS


app = Flask(__name__)

CORS(app, supports_credentials=True,
     origins=[
         "http://localhost:5173",
         "http://127.0.0.1:5173",
         "http://10.92.3.26:5173",
         "http://10.92.3.140:5173"
     ])

from flask import send_from_directory
import os

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    upload_folder = os.path.join(os.path.dirname(__file__), 'uploads')
    return send_from_directory(upload_folder, filename)

app.config['SECRET_KEY'] = 'chave_secreta_projeto_vendas'

UPLOAD_FOLDER = os.path.join('uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    try:
        conn = fdb.connect(
            host='localhost',
            database=r"C:\Users\Aluno\Desktop\ReportaAi\BANCO.FDB",
            user='SYSDBA',
            password='sysdba',
            charset='UTF8'
        )
        return conn
    except Exception as e:
        print("ERRO FIREBIRD:", e)
        return None

from view import *

if __name__ == '__main__':
    print(app.url_map)
    app.run(host='0.0.0.0', port=5000, debug=True)