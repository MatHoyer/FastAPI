from typing import Union
from fastapi import FastAPI, Request
from pydantic import BaseModel
from mysql.connector import Error
import mysql.connector as mysql
from dotenv import load_dotenv
import os

app = FastAPI()
load_dotenv()

def connect_to_db():
    try:
        connection = mysql.connect(
            host='localhost',
            user='root',
            database='contact'
        )
        return connection
    except Error as e:
        print(f"Erreur lors de la connexion à MySQL: {e}")
        return None

def verify_jwt(token, secret_key):
    import jwt
    try:
        decoded_payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return 'Token expired. Get a new one.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Check the secret key and token.'

@app.get("/")
def read_root(request: Request):
    headers = request.headers
    splitted = headers.get('Authorization').split(' ')
    if splitted[0] == 'Bearer':
      user = verify_jwt(splitted[1], os.getenv('JWT_SECRET_TOKEN'))
      return {'message': user}
    return {'message': 'Invalid token'}

def create_jwt(secret_key, user_id):
    import jwt
    import datetime
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valide pendant 1 heure
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

class UserSignUp(BaseModel):
    name: str
    password: str

def hash_password(password: str) -> str:
    import bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

@app.post("/sign-up")
def sign_up(user: UserSignUp):
    cnx = connect_to_db()
    with cnx.cursor() as cursor:
        try:
          cursor.execute('INSERT INTO user (name, password) VALUES (%s, %s)', (user.name, hash_password(user.password)))
          cnx.commit()
          return {
              "message": "Utilisateur créé avec succès",
              "token": create_jwt(os.getenv('JWT_SECRET_TOKEN'), cursor.lastrowid)
          }
        except Error as e:
            return {
                "message": "Error",
                "error": e
              }
        finally:
            cnx.close()


class UserLogin(BaseModel):
    name: str
    password: str

def check_password(password: str, hashed_password: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.post("/login")
def login(user: UserLogin):
    cnx = connect_to_db()
    with cnx.cursor(dictionary=True) as cursor:
        try:
          cursor.execute('SELECT * FROM user WHERE name=%s', (user.name,))
          db_user = cursor.fetchone()
          if not db_user:
              raise Error('User not found')
          if not check_password(user.password, db_user["password"]):
              raise Error('Invalid password')
          return {
              "message": "Connecte",
              "token": create_jwt(os.getenv('JWT_SECRET_TOKEN'), db_user['id'])
          }
        except Error as e:
            return {
                "message": "Error",
                "error": e
              }
        finally:
            cnx.close()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)