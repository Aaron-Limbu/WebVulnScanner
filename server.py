from flask import Flask,request,jsonify
from flask_cors import CORS
from models import db,bcrypt,Users, Programmes
import os 
from dotenv import load_dotenv
import secrets
from datetime import datetime

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
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = Users.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        if not user.token:
            user.token = secrets.token_hex(32)

        db.session.commit()

        return jsonify({
            "message": "Login successful",
            "token": user.token,
            "role": user.role
        }), 200

    return jsonify({"error": "Invalid email or password"}), 401


@app.route('/verify', methods=["GET"])
def verify():
    token = request.headers.get("Authorization")
    print(f"[DEBUG] Received token: {token}")  # Debugging line

    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    user = Users.query.filter_by(token=token).first()

    if user:
        print(f"[DEBUG] User found: {user.email}")  # Debugging line
        return jsonify({"message": "Success!", "user": {"email": user.email, "role": user.role}}), 200
    else:
        print("[-] Invalid session token")
        return jsonify({"error": "Invalid session"}), 401
@app.route("/logout", methods=["GET"])
def logout():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    user = Users.query.filter_by(token=token).first()
    if not user:
        return jsonify({"error": "Invalid token"}), 401

    user.token = None
    user.role = None
    db.session.commit()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/programmes", methods=["GET"])
def get_programmes():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    user = Users.query.filter_by(token=token).first()
    if not user:
        return jsonify({"error": "Invalid session"}), 401

    programmes = Programmes.query.order_by(Programmes.start_date.desc()).all()
    result = []
    for p in programmes:
        result.append({
            "id":p.id,
            "programme_name": p.programme_name,
            "domain_name": p.domain_name,
            "scope": p.scope,
            "outofscope": p.outofscope,
            "start_date": p.start_date.strftime('%Y-%m-%d'),
            "end_date": p.end_date.strftime('%Y-%m-%d'),
            "status": p.status,
            "created_at": p.created_at.strftime('%Y-%m-%d'),
            "username": p.user.username 
        })

    return jsonify(result), 200

@app.route('/addprogrammes', methods=['POST'])
def addprogramme():
    data = request.get_json()
    required_fields = ['programme_name', 'domain_name', 'scope', 'start_date', 'end_date']
    if not data or not all(k in data for k in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Unauthorized: No token provided"}), 401
    
    user = Users.query.filter_by(token=token).first()
    if not user:
        return jsonify({"error": "Unauthorized: Invalid token"}), 401

    try:
        start_date = datetime.strptime(data['start_date'], "%Y-%m-%d")
        end_date = datetime.strptime(data['end_date'], "%Y-%m-%d")
        new_programme = Programmes(
            programme_name=data['programme_name'],
            domain_name=data['domain_name'],
            scope=data['scope'],
            outofscope=data.get('outofscope', ''),
            start_date=start_date,
            end_date=end_date,
            status="Pending",
            user_id=user.id, 
            created_at=datetime.utcnow()
        )
        db.session.add(new_programme)
        db.session.commit()
        return jsonify({"message": "Programme added successfully!"}), 201

    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to add programme: {str(e)}"}), 500
if __name__ == "__main__": 
    try: 
        # os.system('cls')
        app.run(debug=True)
    except KeyboardInterrupt : 
        print("[i] Stopping the server")
    except Exception as e: 
        print("[!] Error in server: ",e)
    # except OSError : 
    #     os.system('clear')
    #     app.run(debug=True)