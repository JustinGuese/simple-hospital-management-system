
from flask import Flask, jsonify, render_template, request, url_for, redirect, session, send_from_directory, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from os import environ
from datetime import datetime
from dotenv import load_dotenv
import pandas as pd

load_dotenv()

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


CREATIONPASSWORD = environ["SECRET_KEY"]
ROLES = ["superadmin", "admin", "unitadmin", "doctor", "nurse", "maintenance", "hospitalview"]
USEREDITROLES = ["superadmin", "admin", "unitadmin", "doctor", "nurse"]
DIAGNOSISROLES = ["nurse", "doctor"]
UNITADDROLE = ["unitadmin", "superadmin", "admin"]

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
    pac_id = db.Column(db.String(8), primary_key=True)
    firstName = db.Column(db.String(64), index=True)
    lastName = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    phone = db.Column(db.String(64), index=True)
    address_street = db.Column(db.String(64), index=True)
    address_streetNr = db.Column(db.Integer, index=True)
    address_plz = db.Column(db.Integer, index=True)
    address_city = db.Column(db.String(64), index=True)
    address_country = db.Column(db.String(64), index=True)
    insurance = db.Column(db.String(64), index=True)
    insuranceOther = db.Column(db.String(64), index=True)
    hospital = db.Column(db.String(120), index=True)
    maindoctor = db.Column(db.String(120), index=True)
    creation_date = db.Column(db.DateTime, index=True)
    lastUpdate_date = db.Column(db.DateTime, index=True)
    
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
    pac_id = db.Column(db.String(8), db.ForeignKey('patients.pac_id'))
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
            return redirect("/login")
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

# @app.route("/getCurrentUserInfo", methods=["GET"])
# @login_required
# def getCurrentUserInfo():
#     user = _getUser(session["email"])
#     return jsonify({"email": user.email, "name": user.name, "role": user.role, "hospital": user.hospital, "unit": user.unit})
    
# @app.route("/getUsers", methods=["GET"])
# @login_required
def __getUsers():
    # this changes dynamically based on which role you have
    if current_user.role not in ["admin", "unitadmin", "doctor"]:
        raise Exception("Only admins or unitadmins can get users for their hospital. Your role is: %s. Please contact support" % current_user.role)
    
    # else get users
    hospital, senderUnit = current_user.hospital, current_user.unit
    if current_user.role in ["admin", "unitadmin", "doctor"]:
        # return all users of that hospital
        users = Patient.query.filter_by(hospital=hospital).all()
    # elif current_user.role == "unitadmin":
    #     users = Patient.query.filter_by(hospital=hospital, maindoctor=senderUnit).all()
        return users
    else:
        raise Exception("Invalid role: ", current_user.role)

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
    # get the latest patients and show them
    users = __getUsers()
    data = []
    for user in users:
        data.append({"firstName": user.firstName, "lastName": user.lastName, "pac_id": user.pac_id, "edit": "<a href='doctor-pac-view?pacid=%s'>Edit</a>" % str(user.pac_id) })
    if len(data) > 0:
        df = pd.DataFrame(data)
        df = df.set_index("pac_id")
        table = df.to_html(render_links=True ,escape=False)
    else:
        table = "No patients yet! Create some to let them show here."
    return render_template("doctor-pac-search.html", patientstable=table)


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
    pacid = request.args.get("pacid")
    if pacid is None:
        flash("No pacid provided")
        return redirect("/doctor-pac-search")
    else:
        patient = Patient.query.filter_by(pac_id=pacid).first()
        if patient is None:
            flash("Patient not found")
            return redirect("/doctor-pac-search")
        else:
            fullStreet = patient.address_street + " " + str(patient.address_streetNr)
            fullAddress = ", ".join([fullStreet, patient.address_city, str(patient.address_plz), patient.address_country])
            return render_template("doctor-pac-view.html", pacid=pacid, firstName = patient.firstName, lastName = patient.lastName, 
                                email = patient.email, phone = patient.phone, fullAddress = fullAddress
                                )

@app.route("/doctor-pac-new-diagnosis", methods=["GET"])
@login_required
def doctor_pac_new_diagnosis():
    if current_user.role in DIAGNOSISROLES:
        return render_template("doctor-pac-new-diagnosis.html")
    else:
        flash("you are not authorized to view this page")
        return redirect("/")

@app.route("/add-new-patient", methods=["POST"])
@login_required
def add_new_patient():
    if current_user.role in USEREDITROLES:
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        phone = request.form['phone']
        street = request.form['street']
        streetnr = int(request.form['streetnr'])
        plz = int(request.form['plz'])
        city = request.form['city']
        country = request.form['country']
        insurance = request.form['insurance']
        insuranceOther = request.form['insurance-other']
        pac_id = generate_password_hash(firstname+lastname+email)[-8:]
        
        # assume same hospital and unit as current user
        userHospital = current_user.hospital
        datetimenow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pat = Patient(pac_id=pac_id, firstName=firstname, lastName=lastname, email=email, phone=phone, address_street=street, address_streetNr=streetnr, address_plz=plz, address_city=city, 
            address_country=country, insurance=insurance, insuranceOther=insuranceOther, hospital=userHospital, creation_date = datetimenow, lastUpdate_date = datetimenow)
        db.session.add(pat)
        db.session.commit()
        return redirect("/doctor-pac-view?pacid=%s" % pac_id)
    else:
        flash("you are not authorized to add a new patient")
        return redirect("/")



## patient functionality
if __name__ == '__main__':
    app.run(host = "0.0.0.0", debug=True)
