from flask import Flask, jsonify, render_template, request, url_for, redirect, session, abort, Response
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from os import environ
from dotenv import load_dotenv
from routes import *

load_dotenv()

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


CREATIONPASSWORD = environ["SECRET_KEY"]
ROLES = ["admin", "unitadmin", "doctor", "sister", "maintenance", "hospitalview"]

app = Flask(__name__)
app.secret_key = environ["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%s:%s@%s:%s/%s' % (
    environ["POSTGRES_USER"],
    environ["POSTGRES_PASSWORD"],
    environ["POSTGRES_HOST"],
    environ["POSTGRES_PORT"],
    environ["POSTGRES_DB"]
)
db = SQLAlchemy(app)

## db models
class User(db.Model):
    __tablename__ = "users"
    email = db.Column(db.String(120), index=True, unique=True, primary_key=True)
    name = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(64), index=True)
    hospital = db.Column(db.String(64), index=True)
    unit = db.Column(db.String(64), index=True)
    is_active = db.Column(db.Boolean, default=True)
    
    def get_id(self):
        return self.email

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_authenticated(self):
        return True
    
class Patient(db.Model):
    __tablename__ = 'patients'
    pac_id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(64), index=True)
    lastName = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    phone = db.Column(db.String(64), index=True)
    address_street = db.Column(db.String(64), index=True)
    address_plz = db.Column(db.Integer(), index=True)
    address_city = db.Column(db.String(64), index=True)
    address_country = db.Column(db.String(64), index=True)
    hospital = db.Column(db.String(120), index=True)
    creation_date = db.Column(db.DateTime, index=True)
    lastUpdate_date = db.Column(db.DateTime, index=True)
    test_type = db.Column(db.String(64), index=True)
    
class Doctors(db.Model):
    __tablename__ = 'doctors'
    doctor_id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(64), index=True)
    lastName = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    phone = db.Column(db.String(64), index=True)
    hospital = db.Column(db.String(120), index=True)
    speciality = db.Column(db.String(64), index=True)
    
class Case(db.Model):
    __tablename__ = 'cases'
    case_id = db.Column(db.Integer, primary_key=True)
    pac_id = db.Column(db.Integer, db.ForeignKey('patients.pac_id'))
    patient = db.relationship("Patient", backref=db.backref("patients", uselist=False))
    stay_from = db.Column(db.DateTime, index=True)
    stay_to = db.Column(db.DateTime, index=True)
    house = db.Column(db.String(64), index=True)
    room = db.Column(db.String(64), index=True)
    doctor_id = db.Column(db.String(64), index=True)
    
class Diagnosis(db.Model):
    __tablename__ = 'diagnoses'
    diagnosis_id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.case_id'))
    # case = db.relationship("Case", backref=db.backref("cases", uselist=False))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'))
    # doctor = db.relationship("Case", backref=db.backref("cases", uselist=False))
    timestamp = db.Column(db.DateTime, index=True)
    category = db.Column(db.String(64), index=True)
    freetext = db.Column(db.String(512), index=True)
    
## end db models

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# simple user model

    
db.create_all()
db.session.commit()


if __name__ == '__main__':
    app.run(host = "0.0.0.0", debug=True)