from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Enum
db=SQLAlchemy()
bcrypt=Bcrypt()


#user model 
class Users(db.Model): 
    id = db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100),nullable=False)
    email = db.Column(db.String(255),unique=True,nullable=False)
    password_hash = db.Column(db.String(255),nullable=False)
    role=db.Column(Enum("pentester","admin","blue_teamer","developer",name="user_roles",nullable=False,default="pentester"))
    
    def __init__(self,username,email,password,role="pentester"): 
        self.username=username
        self.email=email
        self.password_hash=bcrypt.generate_password_hash(password).decode('utf-8')
        self.role=role