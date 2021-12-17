
from flask import Flask, jsonify, render_template, request, url_for, redirect, session, send_from_directory
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from os import environ
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


CREATIONPASSWORD = environ["SECRET_KEY"]
ROLES = ["superadmin", "admin", "unitadmin", "doctor", "nurse", "maintenance", "hospitalview"]

app = Flask(__name__)
app.secret_key = environ["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%s:%s@%s:%s/%s' % (
    environ["POSTGRES_USER"],
    environ["POSTGRES_PASSWORD"],
    environ["POSTGRES_HOST"],
    environ["POSTGRES_PORT"],
    environ["POSTGRES_DB"]
)

@app.route("/assets/<path:path>") # workaround
def static_dir(path):
    return send_from_directory("templates/assets", path)

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
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user is not None and user.check_password(password):
            login_user(user)
            return redirect("/")
        else:
            if user is None:
                return render_template("login.html", error="User not found")
            elif not user.check_password(password):
                return render_template("login.html", error="Wrong password")
            else:
                return {"error": "Invalid username or password"}
    elif request.method == 'GET':
        return render_template('login.html', error = "")
    else:
        raise Exception("Invalid request")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        password_repeat = request.form['password-repeat']
        hospital = request.form['clinic']
        unit = request.form['unit']
        role = request.form['role']
        license = request.form['license-terms']
        user = User.query.filter_by(email=email).first()
        if user is None and password == password_repeat:
            user = User(email=email, name=name, role=role, hospital=hospital, unit=unit)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return redirect("login.html")
        else:
            if user is not None:
                return render_template("register.html", error="User exists, log in instead")
            else:
                raise Exception("Invalid request ", request)
    elif request.method == 'GET':
        return render_template('register.html', error = "")
    else:
        raise Exception("Invalid request")
    
@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("index.html", name = current_user.name)

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
    return render_template("login.html", error = "successfully logged out")


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
    return redirect("/login")

## subpage views
@app.route("/doctor-pac-search", methods=["GET"])
@login_required
def doctor_pac_search():
    return render_template("doctor-pac-search.html")

@app.route("/booking-pac-search", methods=["GET"])
@login_required
def booking_pac_search():
    return render_template("booking-pac-search.html")

@app.route("/booking-new-patient", methods=["GET"])
@login_required
def booking_new_paatient():
    return render_template("booking-new-patient.html")

@app.route("/doctor-pac-view", methods=["GET"])
@login_required
def doctor_pac_view():
    return render_template("doctor-pac-view.html")

@app.route("/doctor-pac-new-diagnosis", methods=["GET"])
@login_required
def doctor_pac_new_diagnosis():
    return render_template("doctor-pac-new-diagnosis.html")



## patient functionality
if __name__ == '__main__':
    app.run(host = "0.0.0.0", debug=True)
