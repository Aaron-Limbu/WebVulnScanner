from flask import Flask,request,jsonify
from flask_cors import CORS
from models import db,bcrypt,Users
import os 
from dotenv import load_dotenv


load_dotenv()
#intializing Flask app
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI']=os.getenv("MYSQL_URI") #config

#initialze database
db.init_app(app)
bcrypt.init_app(app)

#create tables if they dont exists
with app.app_context(): 
    db.create_all()


#Registration Route
@app.route('/register', methods=["POST"])
def register():
    try: 
        data = request.get_json()  # `silent=True` prevents errors if JSON is invalid
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        password2 = data.get("password-confirmation")

        if not username or not email or not password or not password2:
            return jsonify({"error": "All fields are required"}), 400
        if Users.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400
        if password.lower() != password2.lower():
            return jsonify({"error": "Passwords did not match"}), 400

        new_user = Users(username, email, password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e : 
        print("[!] ",e)
#login route
@app.route('/login',methods=["POST"])
def login(): 
    try: 
        data = request.get_json()
        email = data.get("email")
        password= data.get("password")
        user = Users.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash,password): 
            return jsonify({"message":"login successful","role":user.role}),200
        else : 
            return jsonify({"error","Invalid email or password"}),401
    except Exception as e: 
        print("[!] Error",e)



if __name__ == "__main__": 
    try: 
        os.system('cls')
        app.run(debug=True)
    except OSError : 
        os.system('clear')
        app.run(debug=True)