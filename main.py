from flask import Flask,render_template,url_for,request,session
from flask_sqlalchemy import SQLAlchemy
import os
import pathlib
import requests
import google
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from sqlalchemy import create_engine, text
from flask_dance.contrib.github import make_github_blueprint, github
import google.auth.transport.requests

app = Flask(__name__)
app.secret_key = "ye_secret_hai"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "800059057843-mb927eq1dr76bdn496cb32nclj5okp93.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

github_blueprint = make_github_blueprint(client_id='Ov23liWuwV5Ok3lAoMKB',
                                         client_secret='77e9e4d074fe8b6e8ab3ff98fc26c1ce23ccabc6')

app.register_blueprint(github_blueprint, url_prefix='/github_login')


app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://sql12739917:cL7GY2ZSPE@sql12.freesqldatabase.com:3306/sql12739917"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

def generate_otp_number(phone):
    session['number'] = int(phone)
    url = "https://api.rechargezap.in/auth/otp"
    headers = {
        "Host": "api.rechargezap.in",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://rechargezap.in/",
        "Appid": "100002",
        "Content-Type": "application/json",
        "Origin": "https://rechargezap.in",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Priority": "u=0",
        "Te": "trailers"
    }
    data = {"mobileNumber": session['number']}
    response = requests.post(url, headers=headers, json=data).json()
    print(response)
    if response["status"]=="success":
        return {'status':1}
    else:
        return {'status': 0}


def verify_otp_number(number,otp):
    otp = int(otp)
    url = "https://api.rechargezap.in/auth/verify/otp"
    headers = {
        "Host": "api.rechargezap.in",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://rechargezap.in/",
        "Appid": "100002",
        "Content-Type": "application/json",
        "Origin": "https://rechargezap.in",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Priority": "u=0",
        "Te": "trailers"
    }

    data = {
        "mobileNumber": number,
        "otp": otp,
        "name": "nothing here",
        "email": "nothinghere@gmail.com"
    }

    response = requests.post(url, headers=headers, json=data).json()

    if response["status"]=="success":
        return {'message':'OTP verified successfully.'}
    else:
        return {'message':'OTP verification failed.'}

def generate_otp_email(email):
    session['email'] = email
    url = "https://api.dotshowroom.in/api/dotk/vo1/user/login/v2/email"
    headers = {
        "Host": "api.dotshowroom.in",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.digitalhardwaremart.in/",
        "Content-Type": "application/json",
        "Session_id": "c2c3be09-a16e-49f1-b479-f2bb3d33ef48",
        "Auth_token": "null",
        "App_os": "cfe",
        "App_version": "0.1.0",
        "Origin": "https://www.digitalhardwaremart.in",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Priority": "u=0",
        "Te": "trailers"
    }

    data = {
        "email": f"{session['email']}",
        "store_id": 688545
    }

    response = requests.post(url, headers=headers, json=data).json()

    if response["message"]=="Success":
        return {'status': 1}
    else:
        return {'status': 0}



def verify_otp_email(email,otp):
    otp = int(otp)
    url = "https://api.dotshowroom.in/api/dotk/vo1/user/verifyOtp"
    params = {
        "email": f"{email}",
        "otp": otp,
        "store_id": 688545
    }

    headers = {
        "Host": "api.dotshowroom.in",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.digitalhardwaremart.in/",
        "Session_id": "c2c3be09-a16e-49f1-b479-f2bb3d33ef48",
        "Auth_token": "null",
        "App_os": "cfe",
        "App_version": "0.1.0",
        "Origin": "https://www.digitalhardwaremart.in",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Priority": "u=0",
        "Te": "trailers"
    }

    response = requests.get(url, headers=headers, params=params).json()

    if response["message"]=="Success":
        return {'message':'OTP verified successfully.'}
    else:
        return {'message':'OTP verification failed.'}



class student_creds(db.Model):
    rollno = db.Column(db.Integer,primary_key=True,nullable=False)
    name = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    mobile_number = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    father_name = db.Column(db.String(255), nullable=False)
    mother_name = db.Column(db.String(255), nullable=False)
    course = db.Column(db.String(255), nullable=False)
    branch = db.Column(db.String(255), nullable=False)
    maths10 = db.Column(db.Integer, nullable=False)
    science10 = db.Column(db.Integer, nullable=False)
    sst10 = db.Column(db.Integer, nullable=False)
    hindi10 = db.Column(db.Integer, nullable=False)
    english10 = db.Column(db.Integer, nullable=False)
    chemistry12 = db.Column(db.Integer, nullable=False)
    physics12 = db.Column(db.Integer, nullable=False)
    maths12 = db.Column(db.Integer, nullable=False)
    total_marks = db.Column(db.Integer, nullable=False)


@app.route('/',methods=['GET','POST'])
def default():
    return {'status':'API live'}

@app.route('/endpoints')
def endpoints():
    return {
        'login':'Login with user credentials',
        'signup':'Sign up with user credentials',
        'fetch':'Retrieve user credentials'
    }

@app.route('/login',methods = ['GET'])
def get_login():
    return render_template('login.html')

@app.route('/register',methods=['GET'])
def get_register():
    return render_template('registration.html')


@app.route("/callback")
def callback():
    if "error" in request.args:
        return redirect("/register")
    if "google_id" not in session:
        flow.fetch_token(authorization_response=request.url)

        if not session["state"] == request.args["state"]:
            abort(500)

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )
        try:
            new_user = student_creds(email=id_info["email"],name=id_info["name"])
            db.session.add(new_user)
            db.session.commit()
            return {'message': 'Registered successfully'}
        except:
            return {'message': 'USer already exists.'}


@app.route('/login',methods = ['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    print(email,password)
    user = student_creds.query.filter_by(email=email).first()
    if user and user.password == password:
        return {'message': 'Logged in successfully'}
    else:
        return {'message': 'Invalid credentials'}, 401


@app.route('/google_login',methods=["POST","GET"])
def login_gmail():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route('/github_login')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))
    else:
        account_info = github.get('/user')
        if account_info.ok:
            account_info_json = account_info.json()
            print(account_info_json)
            return '<h1>Your Github name is {}'.format(account_info_json['login'])
    return {'message':'success'}


@app.route('/register_email',methods = ['POST'])
def register_email():
    email = request.form['email']
    print(email)
    existing = student_creds.query.filter_by(email=email).first()
    if existing:
        return {'message': 'User already exists'}
    else:
        result = generate_otp_email(email)
        if result['status']==1:
            return {'message':'OTP sent.'}
        else:
            return {'message':'OTP failed.'}

@app.route('/register_phone',methods = ['POST'])
def register_phone():
    phone = request.form['phone']
    print(phone)
    existing = student_creds.query.filter_by(email=phone).first()
    if existing:
        return {'message': 'User already exists'}
    else:
        result = generate_otp_number(phone)
        if result['status']==1:
            return {'message':'OTP sent.'}
        else:
            return {'message':'OTP failed.'}




'''        newuser = student_creds(email=email,mobile_number=num,password=password)
        db.session.add(newuser)
        db.session.commit()
        return {'message': 'Registered successfully'}'''


@app.route('/google_register',methods=["POST","GET"])
def google_register():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route('/github_register')
def github_register():
    if not github.authorized:
        return redirect(url_for('github.login'))
    else:
        account_info = github.get('/user')
        if account_info.ok:
            account_info_json = account_info.json()
            print(account_info_json)
            return '<h1>Your Github name is {}'.format(account_info_json['login'])
    return {'message':'success'}


@app.route('/update_details', methods=['POST'])
def update_details():
    form_data = request.form

    mobile_number = int(form_data.get('mobile_number'))
    email = str(form_data.get('email'))

    print(email,mobile_number)

    # Find the student by email or mobile number
    student = student_creds.query.filter((student_creds.mobile_number == mobile_number) | (student_creds.email == email)).first()
    print(student)

    if student:
        try:
            student.name = form_data.get('student_name')
            student.rollno = form_data.get('roll_number')
            student.father_name = form_data.get('father_name')
            student.mother_name = form_data.get('mother_name')
            student.course = form_data.get('course')
            student.branch = form_data.get('branch')

            # Update Class 12th marks
            student.chemistry12 = int(form_data.get('chem12'))
            student.physics12 = int(form_data.get('phy12'))
            student.maths12 = int(form_data.get('math12'))

            # Update Class 10th marks
            student.maths10 = int(form_data.get('maths10'))
            student.science10 = int(form_data.get('science10'))
            student.sst10 = int(form_data.get('sst10'))
            student.hindi10 = int(form_data.get('hindi10'))
            student.english10 = int(form_data.get('english10'))

            # Update total marks (if required)
            total_12_marks = student.chemistry12 + student.physics12 + student.maths12
            total_10_marks = student.maths10 + student.science10 + student.sst10 + student.hindi10 + student.english10
            student.total_marks = total_12_marks + total_10_marks

            db.session.commit()
            return {'message': 'Student details updated successfully!'}
        except:
            print("Exception at line 371")
    else:
        return {'error': 'Student not found with the given email or mobile number.'}


@app.route('/admin_register',methods=['GET'])
def get_admin_register():
    return render_template('adminre.html')

@app.route('/admin_login',methods=['GET'])
def get_admin_login():
    return render_template('adminlogi.html')

@app.route('/dashboard',methods=['GET'])
def get_dashboard():
    return render_template('dashbord.html')

def test_db_connection():
    try:
        # Run a simple query to test the connection
        result = db.session.execute(text("SELECT * FROM student_creds WHERE mobile_number = :mobile_number;"),
                                     {'mobile_number': 8755868585})  # Use parameter binding

        student_record = result.fetchone()  # Fetch a single record

        if student_record:
            print(f"Connected to database. Student Record: {student_record}")
            return f"Connected to database. Student Record: {student_record}"
        else:
            print("No records found for the given mobile number.")
            return "No records found for the given mobile number."
    except Exception as e:
        print(f"Error: {e}")
        return f"Database connection failed: {str(e)}"

@app.route('/test_db')
def test_db():
    return test_db_connection()



if __name__ == '__main__':
    app.run(debug=True)