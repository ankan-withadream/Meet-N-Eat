from flask import Flask, session, request, flash, url_for, jsonify
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect
import requests
from flask_login import UserMixin, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
from functools import wraps
import jwt
import datetime
from werkzeug.exceptions import HTTPException


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///MeetNEat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='ExampleSecretKey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not 'user' in session:
            flash('You need to login first :(')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def owner_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session['username']
        check_user = users.query.filter_by(username=username).first()
        if check_user.is_owner == True:
            return f(*args, **kwargs)
        elif check_user.is_admin == True:
            return f(*args, **kwargs)
        else:
            flash("Sorry you are not a resturant owner :(")
            return redirect("/home")
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session['username']
        check_user = users.query.filter_by(username=username).first()
        if check_user.is_admin == True:
            return f(*args, **kwargs)
        else:
            flash("Sorry you are not an admin :(")
            return redirect("/home")
    return decorated_function

# @app.errorhandler(HTTPException)   #Error handling
# def handle_exception(e):
#     response = str(e.code) + " error: " + str(e.name) + " :( "
#     if 'user' in session:
#         flash(response)
#         return redirect("/home")
#     else:
#         flash(response)
#         return redirect("/")

class users(db.Model, UserMixin):
    id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(15), nullable=False, primary_key=True, unique=True)
    password = db.Column(db.String(100), nullable=False)
    is_owner = db.Column(db.Boolean, nullable=True)
    is_admin = db.Column(db.Boolean, nullable=True)
    owned_rst_id = db.Column(db.Integer, nullable=True)

class signup_form(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=10)])
    password = PasswordField(validators=[InputRequired()])
    submit = SubmitField("Sign Up")

class login_form(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=10)])
    password = PasswordField(validators=[InputRequired()])
    submit = SubmitField("Log In")
    

class rstrnt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rstrnt_name = db.Column(db.String(20), unique=True, nullable=False)
    rstrnt_loct = db.Column(db.String(40), unique=False, nullable=False)
    
    def __repr__(self):
        rst_loct = self.rstrnt_loct.replace("+", " ")
        output = {"resturant_id": (self.id), "resturant_name": (self.rstrnt_name), "resturant_location": (rst_loct)}
        return str(output)
        
    def rstid(self):
        return (self.id)

class srchrslt(db.Model):
    id = db.Column(db.String(20), primary_key=True, nullable=False)
    name = db.Column(db.String(20), nullable=False)
    loct = db.Column(db.String(80), nullable=False)
    food = db.Column(db.String(10), nullable=False)
 
    def __repr__(self):
        return f"{self.id} \n {self.name} \n {self.loct} \n {self.food}"

class resturant_availabelity(db.Model):
    food_id = db.Column(db.Integer, primary_key=True)
    rstrnt_ids = db.Column(db.String, nullable=False)

class food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

    def __repr__(self):
        return f"{self.id} \n {self.name}"

class update_req(db.Model):
    req_id = db.Column(db.Integer, primary_key=True)
    req_rst_id = db.Column(db.Integer, nullable=False)
    new_name = db.Column(db.String)
    new_address = db.Column(db.String)

class Orders(db.Model):
    order_id = db.Column(db.Integer, primary_key=True)
    orders = db.Column(db.String, nullable=True)
    food_lst = db.Column(db.String, nullable=True)
    username = db.Column(db.String, nullable=True)
    rstrnt_id = db.Column(db.Integer, nullable=True)
    meal_type = db.Column(db.String, nullable=True)
    order_time = db.Column(db.DateTime, nullable=True)

class Logs(db.Model):
    log_id = db.Column(db.Integer, primary_key=True)
    log_msg = db.Column(db.String, nullable=True)
    username = db.Column(db.String, nullable=True)
    log_time = db.Column(db.DateTime, nullable=True)

@app.route("/")
def home():
    if 'user' in session:
        return redirect("/home")
    else:
        return render_template('index.html')

@app.route("/home")
def get_home():
    return render_template('home.html')

@app.route("/resturants")
# @login_required
def all_resturants():
    scheduling = False
    show_rstrnt = rstrnt.query.all()
    return render_template('all_resturants.html', rstrnt=show_rstrnt, scheduling = scheduling)

@app.route("/resturants/foods/<int:id>")
@login_required
def show_available_foods(id):
    if not rstrnt.query.filter_by(id=id).first(): #Exception Handling -- If wrong resturant id entered
        flash("No such restaurant found :(")
        return redirect("/resturants")
    showing_food = True
    food_lst = []
    food_name_lst = []
    fds = resturant_availabelity.query.all()
    for i in fds:
        for j in i.rstrnt_ids:
            if (int(j)==id):
                fdid = i.food_id
                food_lst.append(fdid)
    for i in food_lst:
        x = food.query.get(i)
        food_name_lst.append(x.name)

    return render_template("food.html",food_lst=food_lst, food_name_lst=food_name_lst, showing_food=showing_food, fdlen = len(food_lst), rst_id=id)

@app.route("/resturants/foods/add/<int:rst_id>", methods=['GET', 'POST'])
@login_required
@owner_or_admin_required
def add_food_in_resturant(rst_id):
    if request.method=='POST':
        if not rstrnt.query.filter_by(id=rst_id).first(): #Exception Handling -- If wrong resturant id entered
            flash("No such restaurant found :(")
            return redirect(f"/resturants")
        food2badd_name = request.form['food_name']
        fds = food.query.all()
        for i in fds:
            if i.name==food2badd_name:
                food_id = int(i.id)
                food_id_x = resturant_availabelity.query.filter_by(food_id=food_id).first()
                food_id_xs = str(food_id_x.rstrnt_ids)
                rst_id_s = str(rst_id)
                if rst_id_s in food_id_xs:
                    flash("This food item already exists in this resturant :(")
                    return redirect(f"/resturants/foods/{rst_id}")
                else:
                    food_id_xs = food_id_xs + rst_id_s
                    food_id_x.rstrnt_ids = food_id_xs
                    db.session.commit()
                    username = session['username']                 #Saving in logs
                    food_obj = food.query.filter_by(id=food_id).first()
                    food_name = food_obj.name
                    rst_obj = rstrnt.query.filter_by(id=rst_id).first()
                    rstrnt_name = rst_obj.rstrnt_name
                    log_msg = f"{username} added a food item {food_name} to {rstrnt_name}"
                    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
                    db.session.commit()
                    return redirect(f"/resturants/foods/{rst_id}")
        flash("This food item does not exist in database :(  please add this food first")
        return redirect(f"/resturants/foods/{rst_id}")

@app.route("/resturants/foods/delete/<int:rst_id>/<int:food_id>")
@login_required
@owner_or_admin_required
def delete_food_from_resturant(rst_id, food_id):
    if not rstrnt.query.filter_by(id=rst_id).first(): #Exception Handling -- If wrong resturant id entered
        flash("No such restaurant found :(")
        return redirect(f"/resturants")
    elif not resturant_availabelity.query.filter_by(food_id=food_id).first(): #Exception Handling -- If wrong food id entered
        flash("No such food item found :( ")
        return redirect(f"/resturants/foods/{rst_id}")
    to_be_dlt = resturant_availabelity.query.get(food_id)
    new_rstids = to_be_dlt.rstrnt_ids.replace(str(rst_id), "")
    db.session.delete(to_be_dlt)
    db.session.add(resturant_availabelity(food_id=food_id, rstrnt_ids=new_rstids))
    db.session.commit()
    username = session['username']                 #Saving in logs
    food_obj = food.query.filter_by(id=food_id).first()
    food_name = food_obj.name
    rst_obj = rstrnt.query.filter_by(id=rst_id).first()
    rstrnt_name = rst_obj.rstrnt_name
    log_msg = f"{username} added a food item {food_name} to {rstrnt_name}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    return redirect(f"/resturants/foods/{rst_id}")

@app.route("/foods") 
def all_foods():
    show_foods = food.query.all()
    return render_template("food.html", foods=show_foods)

@app.route("/foods/resturants/<int:id>") 
def resturants_available_forthis_food(id):
    if not food.query.get(id): #Exception Handling -- If wrong food id entered
        flash("No such food item found :(")
        return redirect("/foods")
    the_food = resturant_availabelity.query.get(id)
    food_name = (food.query.get(id)).name
    rsts = the_food.rstrnt_ids
    rst_lst = []
    for i in rsts:
        rst= rstrnt.query.get(i)
        rst_lst.append({"resturant_id":rst.id, "resturant_name":rst.rstrnt_name, "resturant_loct":rst.rstrnt_loct.replace("+", " ")})
    return render_template("available_resturants.html", rst_lst=rst_lst, food_name=food_name)

@app.route("/foods/add", methods=['GET', 'POST'])
@login_required
@admin_required
def add_food():
    adding_food = True
    if request.method=='POST':
        name=request.form['rstrnt_name']
        if food.query.filter_by(name=name).first(): #Exception Handling -- If wrong food id entered
            flash("Food Item already added")
            return redirect("/foods")
        this_food = food(name=name)
        db.session.add(this_food)
        db.session.commit()
        food_id = this_food.id
        this_food_ra = resturant_availabelity(food_id=food_id, rstrnt_ids="")
        db.session.add(this_food_ra)
        db.session.commit()
        username = session['username']                 #Saving in logs
        food_obj = food.query.filter_by(id=food_id).first()
        food_name = food_obj.name
        log_msg = f"{username} added a food item {food_name}"
        db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
        db.session.commit()
        flash("Food added in list :) ")
        return redirect("/foods/add")
        
    return render_template("add.html", adding_food=adding_food)

@app.route("/foods/delete/<int:id>")
@login_required
@admin_required
def delete_food(id):
    try: #Exception Handling -- If wrong food id entered
        get_food = food.query.get(id)
    except Exception:
        flash("Wrong food id provided in the url -_-")
        return redirect("/foods")
    get_food_from_ra = resturant_availabelity.query.get(id)
    db.session.delete(get_food)
    db.session.delete(get_food_from_ra)
    db.session.commit()
    username = session['username']                 #Saving in logs
    food_obj = food.query.filter_by(id=id).first()
    food_name = food_obj.name
    log_msg = f"{username} deleted a food item {food_name}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    return redirect("/foods")

@app.route("/update/<int:id>", methods=['GET', 'POST'])
@login_required
@admin_required
def update_rstrnt(id):
    if not rstrnt.query.filter_by(id=id).first(): #Exception Handling -- If wrong resturant id entered
        flash("Wrong resturant id given in url :(")
        return redirect("/resturants")
    updt_rstrnt = rstrnt.query.filter_by(id=id).first()
    if request.method == 'POST':
        old_name = updt_rstrnt.rstrnt_name
        old_loct = updt_rstrnt.rstrnt_loct
        updt_rstrnt.rstrnt_name = request.form['name']
        updt_rstrnt.rstrnt_loct = request.form['loct']
        db.session.commit()
        username = session['username']                    #Saving in Logs
        rst_obj = rstrnt.query.filter_by(id=id).first()
        rstrnt_name = rst_obj.rstrnt_name
        log_msg = f"{username} updated a resturant {rstrnt_name}'s data: {old_name} to {updt_rstrnt.rstrnt_name}  and {old_loct} to {updt_rstrnt.rstrnt_loct}"
        db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
        db.session.commit()
        return redirect("/resturants")
    return render_template("update.html", updt_rstrnt=updt_rstrnt)

@app.route("/delete/<int:id>")
@login_required
@admin_required
def dlt_rstrnt(id):
    if not rstrnt.query.filter_by(id=id).first(): #Exception Handling -- If wrong resturant id entered
        flash("Wrong resturant id given in url :(")
        return redirect("/resturants")
    dlt_rst = rstrnt.query.filter_by(id=id).first()
    db.session.delete(dlt_rst)
    db.session.commit()
    username = session['username']                    #Saving in Logs
    rst_obj = rstrnt.query.filter_by(id=id).first()
    rstrnt_name = rst_obj.rstrnt_name
    log_msg = f"{username} deleted a resturant {rstrnt_name}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    return redirect("/resturants")

@app.route("/add", methods=['GET', 'POST'])
@login_required
@owner_or_admin_required
def add_resturant():
    username = session['username']
    check_user = users.query.filter_by(username=username).first()
    if check_user.owned_rst_id:
        if check_user.is_owner==True:
            flash("You already added your resturant -_-")
            return redirect("/home")
    else:
        if request.method == 'POST':
            loct = str(request.form['rstrnt_loct']).replace(" ", '+')
            new_rstrnt = rstrnt(rstrnt_name=request.form['rstrnt_name'], rstrnt_loct=loct)
            try:            #Exception Handling -- If resturant name already exists
                db.session.add(new_rstrnt)
                db.session.commit()
                username = session['username']                 #Saving in logs
                log_msg = f"{username} added a resturant {new_rstrnt.rstrnt_name}"
                db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
                db.session.commit()
                if check_user.is_owner == True:
                    check_user.owned_rst_id = new_rstrnt.id
                    db.session.commit()
                return redirect("/add")
            except Exception:
                flash("This resturant is already added")
                db.session.rollback()
            next = session['next']
            if next:
                return redirect(next)
            return redirect("/home")
    return render_template('add.html')

@app.route("/find", methods=['GET', 'POST'])
def find_resturant():
    if request.method == 'POST':
        src_rslt=rstrnt.query.filter_by(rstrnt_loct=request.form['rstrnt_loct']).all()
        return render_template("find_result.html", src_rslt=src_rslt)
    return render_template('find.html')

@app.route("/takelove")
def take_love():
    return render_template('love.html')

@app.route("/apifind", methods=['GET', 'POST'])
def find_resturant_api():
    if request.method=='POST':
        food=request.form['food']
        place=request.form['loct']
        str(place).replace(" ", '+')
        geocoding_key = 'ExampleKey' #Generate your own key from mapquestapi's site
        url_loc = "http://open.mapquestapi.com/geocoding/v1/address?key={}&location={}".format(geocoding_key, place)
        lct_rslt = requests.get(url_loc).json()
        lat = lct_rslt['results'][0]['locations'][0]['latLng']['lat']
        lng = lct_rslt['results'][0]['locations'][0]['latLng']['lng']

        client_id_frsqr = 'Example_Key' #Generate your own key from Foursquare's site
        client_secret_frsqr = 'Example_key' #Generate your own key from Foursquare's site
        limit = 5
        v = 20210620
        query = food
        url_frsqr = "https://api.foursquare.com/v2/venues/search?ll={},+{}&limit={}&query={}&client_id={}&client_secret={}&v={}".format(lat,lng,limit,query,client_id_frsqr,client_secret_frsqr,v)
        rslt = requests.get(url_frsqr).json()
        for i in srchrslt.query.all():
            db.session.delete(i)
            db.session.commit()
        for i in rslt['response']['venues']:
            new_rslt = srchrslt(id = i['id'], name = i['name'], loct = i['location']['address'], food = food)
            db.session.add(new_rslt)
            db.session.commit()
        return redirect("/search_result")
    return render_template('apifind.html')

@app.route("/search_result")
def all_result():
    show_rslt = srchrslt.query.all()
    return render_template('apifindresult.html', srchrslt=show_rslt)

@app.route("/get_resturant/username=<string:username>&password=<string:password>&token=<string:token>&address=<string:address>")
def get_rstrnts(username, password, token, address):
    address_replaced = str(address).replace(" ", '+')
    get_usr = users.query.filter_by(username=username).first()
    token_user = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS512')
    token_username = token_user['data']
    if bcrypt.check_password_hash(get_usr.password, password):
        if token_username==get_usr.username:
            get_rstrnt = rstrnt.query.filter_by(rstrnt_loct=address_replaced).all()
            return str(get_rstrnt)
        else:
            return jsonify('Invalid token :(')

@app.route("/get_token")
@login_required
def get_token():
    user = session['user']
    payload = {'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
                'iat': datetime.datetime.utcnow(),
                'data': user,}
    if 'token' in session:
        session.pop('token', None)
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS512')
    session['token'] = token
    # return jsonify({token: 'token.decode utf-8'})
    return render_template("home.html", token=token)

@app.route("/suggest/update/<int:id>", methods=['GET', 'POST'])
@login_required
def suggested_update(id):
    if not rstrnt.query.filter_by(id=id).first(): #Exception Handling -- If wrong resturant id given
        flash("Wrong resturant id given in url :(")
        return redirect("/resturants")
    rst = rstrnt.query.filter_by(id=id).first()
    old_loct = rst.rstrnt_loct.replace("+", " ")
    suggesting = True
    if request.method == 'POST':
        name = request.form['new_name']
        loct = request.form['new_loct']
        loct_replaced = loct.replace(" ","+")
        suggest = update_req(req_rst_id=id, new_name=name, new_address=loct_replaced)
        db.session.add(suggest)
        db.session.commit()
        username = session['username']                 #Saving in logs
        log_msg = f"{username} suggested an update for resturant {rst.rstrnt_name}: {rst.rstrnt_name} to {suggest.new_name}  and {rst.rstrnt_loct} to {suggest.new_address} >> Update request id: {suggest.req_id} and resturant id: {rst.id}"
        db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
        db.session.commit()
        flash("Your valuable suggestion has been successfully sent to server ^_^")
        return redirect("/resturants")
    return render_template('add.html', suggesting=suggesting, old_name=rst.rstrnt_name, old_loct=old_loct, rst_id=id)

@app.route("/suggestion")
@login_required
@admin_required
def show_suggesstions():
    sgsts = update_req.query.all()
    return render_template('suggestion.html', sgsts=sgsts)

@app.route("/suggestion/update/<int:req_id>/<int:rst_id>")
@login_required
@admin_required
def approve_suggestions(req_id, rst_id):
    if not rstrnt.query.filter_by(id=rst_id).first(): #Exception Handling -- If wrong resturant id entered
        flash("Wrong resturant id given in url :(")
        return redirect("/suggestion")
    elif not update_req.query.filter_by(req_id=req_id).first(): #Exception Handling -- If wrong suggestion id entered
        flash("Wrong suggestion id given in url :(")
        return redirect("/suggestion")
    rst = rstrnt.query.filter_by(id=rst_id).first()
    req = update_req.query.filter_by(req_id=req_id).first()
    rst.rstrnt_name = req.new_name
    rst.rstrnt_loct = req.new_address
    db.session.delete(req)
    db.session.commit()
    username = session['username']                 #Saving in logs
    log_msg = f"{username} approved a suggestion: Request id: {req_id} for Resturant id: {rst_id}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    return redirect("/suggestion")

@app.route("/suggestion/delete/<int:req_id>")
@login_required
@admin_required
def delete_suggestion(req_id):
    if not update_req.query.filter_by(req_id=req_id).first(): #Exception Handling -- If request id does not exist
        flash("Wrong suggestion id given in url :(")
        return redirect("/suggestion")
    req = update_req.query.filter_by(req_id=req_id).first()
    db.session.delete(req)
    db.session.commit()
    username = session['username']                 #Saving in logs
    log_msg = f"{username} approved a suggestion: Request id: {req_id}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    return redirect("/suggestion")

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form=signup_form()
    if request.method=='POST':
        if form.validate_on_submit():
            username = form.username.data
            if users.query.filter_by(username=username).first(): #Exception Handling --if username already exists
                flash("This username already exists. Try diffrent one")
                return redirect("/signup")
            h_pass = bcrypt.generate_password_hash(form.password.data)
            user = users(username=username, password=h_pass)
            db.session.add(user)
            db.session.commit()
            log_msg = f"{user.username} created a new account"     #Saving in Logs
            db.session.add(Logs(log_msg=log_msg, username=user.username, log_time=datetime.datetime.utcnow()))
            db.session.commit()
            if request.form["is_owner"] == "true":
                user.is_owner = True
                db.session.commit()
            elif request.form["is_owner"] == "false":
                user.is_owner = False
                db.session.commit()
            flash("Account has been created :)")
            return redirect("/login")
        else:
            flash("Username must be minimum of 4 and maximum of 10 characters")
            return redirect("/signup")
    return render_template("signup.html", form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form=login_form()
    if request.method == 'POST':
        if form.validate_on_submit():
            check_usr = users.query.filter_by(username=form.username.data).first()
            user = form.username.data
            if check_usr:
                if bcrypt.check_password_hash(check_usr.password, form.password.data):
                    session['user'] = user
                    session['username'] = check_usr.username
                    log_msg = f"{check_usr.username} logged in"
                    db.session.add(Logs(log_msg=log_msg, username=check_usr.username, log_time=datetime.datetime.utcnow()))
                    db.session.commit()
                    next = request.form['next']
                    session['next'] = next
                    if check_usr.is_admin == True:
                        session['is_admin'] = True
                    else:
                        session['is_admin'] = False
                    if check_usr.is_owner == True:
                        session['is_owner'] = True
                    else:
                        session['is_owner'] = False
                    if not check_usr.owned_rst_id:
                        if check_usr.is_owner== True:
                            return redirect("/add")
                    if next:
                        return redirect(next)
                    else:
                        return redirect("/home")
                else:
                    flash("Incorrect password :(")
                    return redirect("/login")
            else:
                flash("Username you entered does not exist :(")
                return redirect("/login")
                   
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    if 'user' in session:
        username = session['username']
        log_msg = f"{username} logged out"
        db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
        db.session.commit()
        session.pop('user', None)
        session.pop('is_admin', None)
        session.pop('is_owner', None)
        session.pop('username', None)
        flash("Logged out successfully :)")
        return redirect("/")
    else:                               #Exception Handling -- If not logged in
        flash("You didn't logged in yet XD")
        return redirect("/login")

@app.route("/make_admin/<string:username>")
@login_required
# @admin_required
def make_admin(username):
    if not users.query.filter_by(username=username).first(): #Exception Handling -- If wrong username given
        flash("User does'n exists :( ")
        return redirect("/home")
    user = users.query.filter_by(username=username).first()
    user.is_admin = True
    db.session.commit()
    username_now = session['username']
    log_msg = f"{username} was made admin by {username_now}"
    db.session.add(Logs(log_msg=log_msg, username=username_now, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    flash("He is now a admin")
    return redirect("/home")

@login_required
@app.route("/schedule_meal")
def show_schedule_meal():
    scheduling = True
    rstrnts = rstrnt.query.all()
    return render_template('all_resturants.html', scheduling = scheduling, rstrnt=rstrnts)

@login_required
@app.route("/schedule_meal/<int:rst_id>")
def schedule_meal(rst_id):
    food_lst = []
    food_name_lst = []
    fds = resturant_availabelity.query.all()
    for i in fds:
        for j in i.rstrnt_ids:
            if (int(j)==rst_id):
                fdid = i.food_id
                food_lst.append(fdid)
    for i in food_lst:
        x = food.query.get(i)
        food_name_lst.append(x.name)
    if 'orders' not in session:
        order = ""
        session['orders'] = order
    cart_ids = session['orders']
    cart = []
    for i in cart_ids:
        food_x = food.query.filter_by(id=str(i)).first()
        cart.append(food_x.name)

    return render_template("food_order.html",food_lst=food_lst, food_name_lst=food_name_lst, fdlen = len(food_lst), rst_id=rst_id, cart=cart)

@login_required
@app.route("/schedule_meal/add/<int:rst_id>/<int:food_id>")
def add_to_menu(rst_id, food_id):
    if 'orders' not in session:
        order = ""
        session['orders'] = order 
    old_order = session['orders']
    new_order = str(old_order) + str(food_id)
    session['orders'] = new_order
    flash("Food added to menu :)") 
    return redirect(f"/schedule_meal/{rst_id}")

@login_required
@app.route("/schedule_meal/schedule/<int:rst_id>", methods=['GET', 'POST'])
def schedule_meal_order(rst_id):
    if request.method == 'POST':
        orders = session['orders']
        foods = ""
        for i in orders:
            food_id = int(i)
            the_food = food.query.filter_by(id=food_id).first()
            foods = foods + str(the_food.name) + ", "
        username = session['username']
        meal_type = request.form['meal_type']
        order_x = Orders(orders=orders, username=username, food_lst=foods, rstrnt_id=rst_id, meal_type = meal_type, order_time = datetime.datetime.utcnow() )
        db.session.add(order_x)
        db.session.commit() #Saving in logs
        log_msg = f"{username} Scheduled an meal. Order id: {order_x.order_id}"
        db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
        db.session.commit()
        session.pop('orders', None)
        flash("Your meal has been scheduled :)")
        return redirect("/schedule_meal")
    return render_template("food_order.html")

@login_required
@owner_or_admin_required
@app.route("/pending_orders")
def show_pending_orders():
    if session['is_owner']:
        username = session['username']
        user = users.query.filter_by(username=username).first()
        rst_id = user.owned_rst_id
        orders = Orders.query.filter_by(rstrnt_id=rst_id).all()
        return render_template("orders.html", orders=orders)
    else:
        orders = Orders.query.all()
        return render_template("orders.html", orders=orders)

@login_required
@owner_or_admin_required
@app.route("/pending_orders/check/<int:order_id>")
def check_pending_order(order_id):
    order2be = Orders.query.filter_by(order_id=order_id).first()
    db.session.delete(order2be)
    db.session.commit()
    username = session['username']                 #Saving in logs
    log_msg = f"{username} checked an order as completed. Order id: {order_id}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    flash("Order has been checked as completed successfully :)")
    return redirect("/pending_orders")

@login_required
@app.route("/my_orders")
def show_my_orders():
    username = session['username']
    orders = Orders.query.filter_by(username=username).all()
    return render_template("orders.html", orders=orders)

@login_required
@app.route("/my_orders/cancel/<int:order_id>")
def cancel_my_orders(order_id):
    order2be = Orders.query.filter_by(order_id=order_id).first()
    db.session.delete(order2be)
    db.session.commit()
    username = session['username']                 #Saving in logs
    log_msg = f"{username} canceled an order. Order id: {order_id}"
    db.session.add(Logs(log_msg=log_msg, username=username, log_time=datetime.datetime.utcnow()))
    db.session.commit()
    flash("Your scheduled meal has been canceled")
    return redirect("/home")

@app.route("/logs")
@login_required
@admin_required
def all_activities():
    logs = Logs.query.all()
    return render_template("logs.html", logs=logs)

@app.route("/clear_logs")
@login_required
@admin_required
def clear_logs():
    logs = Logs.query.all()
    for i in logs:
        db.session.delete(i)
        db.session.commit()
    return redirect("/logs")

if __name__ =="__main__":
    app.run(debug=True)


