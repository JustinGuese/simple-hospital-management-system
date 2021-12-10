
from flask import Flask, jsonify, render_template, request, url_for, redirect, session, abort, Response
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from os import environ
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SubmitField, TextField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from wtforms import ValidationError

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

# DB MODELS
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

# FORMS

class LoginForm(FlaskForm):
    email = TextField('Email',
            validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

    def validate(self):
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if not user:
            self.email.errors.append('Unknown email')
            return False
        if not user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False
        return True


class RegisterForm(FlaskForm):
    name = TextField('Name', validators=[DataRequired(), Length(min=6, max=40)])
    email = TextField('Email',
            validators=[DataRequired(), Email(), Length(min=6, max=40)])
    password = PasswordField('Password',
            validators=[DataRequired(), Length(min=8, max=64)])
    confirm = PasswordField('Verify password',
            validators=[DataRequired(), EqualTo('password',
            message='Passwords must match')])
    hospital = TextField('Hospital',
            validators=[DataRequired(), Length(min=6, max=64)])
    unit = TextField('Unit',
            validators=[DataRequired(), Length(min=1, max=64)])
    role = SelectField(u'Field name', choices = ["doctor", "nurse", "maintenance"], validators = [DataRequired()])



    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)

    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("Email already registered")
            return False
        return True
# END FORMS

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# simple user model

    
db.create_all()
db.session.commit()

# ROUTES ##
# somewhere to login
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            redirect_url = request.args.get('next') or url_for('main.login')
            return redirect(redirect_url)
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        resp = _addUser(form.email.data, form.name.data, form.password.data, form.role.data, form.hospital.data, form.unit.data)
        print(resp)
        if resp.code == 200:
            return redirect(url_for('app.login'))
        else:
            return resp
    return render_template('register.html', form=form)

def _addUser(email, name, password, role, hospital, unit):
    # else create user
    if role not in ROLES:
        return jsonify({"error": "Wrong role: %s. Must be one of: %s" % (role, str(ROLES))}), 401
    
    user = User(email=email, name=name, role=role, hospital = hospital, unit = unit)
    user.set_password(password)
    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({"success": "User created successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Error creating user: %s" % e.args[0]}), 400
    
    
def _getUser(email):
    user = User.query.filter_by(email=email).first()
    return user

def _gethospitalAndUnit(email):
    user = User.query.filter_by(email=email).first()
    if user is None:
        return {"code" : 404, "message" : "User not found"}
    else:
        hospital = user.hospital
        unit = user.unit
    return hospital, unit

def _isOneAdmin(user):
    if user.role in ["admin", "unitadmin"]:
        return True
    else:
        return False

# really only used for hardcore admins
@app.route("/createUserAdmin", methods=["POST"])
def createUserAdmin():
    data = request.get_json()
    try:
        email = data["email"]
        password = data["password"]
        creationpassword = data["creationpassword"]
        name = data["name"]
        role = data["role"]
        # hospital structure
        hospital = data["hospital"]
        unit = data["unit"]
    except KeyError as e:
        return jsonify({"error": "Missing key %s" % e.args[0]}), 400
    
    if creationpassword != CREATIONPASSWORD:
        return jsonify({"error": "Wrong creation password"}), 401
    
    # else create user 
    return _addUser(email, name, password, role, hospital, unit)

@app.route("/createUser", methods=["POST"])
@login_required
def createUser():
    # first check if admin
    user = _getUser(session["email"])
    if not _isOneAdmin(user):
        return jsonify({"error": "Only admins can create users for their hospital. Please contact support"}), 401
    
    data = request.get_json()
    try:
        email = data["email"]
        password = data["password"]
        name = data["name"]
        role = data["role"]
        unit = data.get("unit") # optional if admin
    except KeyError as e:
        return jsonify({"error": "Missing key %s" % e.args[0]}), 400
    
    # if admin then set hospital to the hospital of message sender
    hospital, senderUnit = _gethospitalAndUnit(session["email"])
    
    if unit is None and role == "admin":
        unit = "admin"
    elif unit is None and role == "unitadmin":
        unit = senderUnit
    elif unit is None:
        return jsonify({"error": "Unit not specified"}), 400
    
    return _addUser(email, name, password, role, hospital, unit)
    
@app.route("/getCurrentUserInfo", methods=["GET"])
@login_required
def getCurrentUserInfo():
    user = _getUser(session["email"])
    return jsonify({"email": user.email, "name": user.name, "role": user.role, "hospital": user.hospital, "unit": user.unit})
    
@app.route("/getUsers", methods=["GET"])
@login_required
def getUsers():
    # this changes dynamically based on which role you have
    user = _getUser(session["email"])
    if not _isOneAdmin(user):
        return jsonify({"error": "Only admins or unitadmins can get users for their hospital. Please contact support"}), 401
    
    # else get users
    try:
        hospital, senderUnit = _gethospitalAndUnit(session["email"])
        if user.role == "admin":
            # return all users of that hospital
            users = User.query.filter_by(hospital=hospital).all()
        elif user.role == "unitadmin":
            users = User.query.filter_by(hospital=hospital, unit=senderUnit).all()
        
        return jsonify([{"email": u.email, "name": u.name, "role": u.role, "hospital": u.hospital, "unit": u.unit} for u in users])
    except Exception as e:
        return jsonify({"error": "Error getting users: %s" % e.args[0]}), 500

# somewhere to logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return {"success" : "user logged out"}, 200


# callback to reload the user object        
@login_manager.user_loader
def load_user(email):
    try:
        #: Flask Peewee used here to return the user object
        u = User.query.filter_by(email=email).first()
        return u
    except Exception as e:
        print(e)
        return None

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'please login du spasst', 401

## patient functionality
if __name__ == '__main__':
    app.run(host = "0.0.0.0", debug=True)

