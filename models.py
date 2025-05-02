from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Enum
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

# User model
class Users(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(Enum("pentester", "admin", "blue_teamer", "developer", name="user_roles"), nullable=False, default="pentester")
    token = db.Column(db.String(64), unique=True, nullable=True)  
    programmes = db.relationship("Programmes", backref="user", lazy=True)

    def __init__(self, username, email, password, role="pentester"): 
        self.username = username
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role
        self.token = None

# Programmes model
class Programmes(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    programme_name = db.Column(db.String(100), nullable=False)
    domain_name = db.Column(db.String(100), nullable=False)
    scope = db.Column(db.String(200), nullable=False)
    outofscope = db.Column(db.String(200), nullable=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(Enum("Pending", "Completed", name="status"), nullable=False, default="Pending")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    feedback = db.relationship("Feedback", backref="programme", lazy=True)
    scan_results = db.relationship("ScanResults", backref="programme", lazy=True)

# Feedback model
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    programme_id = db.Column(db.Integer, db.ForeignKey('programmes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("Users", backref="feedback_given")

# Scan results model
class ScanResults(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    programme_id = db.Column(db.Integer, db.ForeignKey('programmes.id'), nullable=False)
    result_type = db.Column(db.String(50), nullable=False)  # e.g., subdomain, header, port
    details = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
