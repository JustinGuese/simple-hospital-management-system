
from forms import LoginForm, RegisterForm
from flask import Flask, jsonify, render_template, request, url_for, redirect, session, abort, Response
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user 
from dbmodels import app, db, User, ROLES, CREATIONPASSWORD, login_manager


# somewhere to login
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            redirect_url = request.args.get('next') or url_for('main.login')
            return redirect(redirect_url)
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        _addUser(form.email.data, form.name.data, form.password.data, form.role.data, form.hospital.data, form.unit.data)
        return redirect(url_for('app.login'))
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
