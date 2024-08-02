import datetime, sys , os
from decimal import Decimal
import boto3
import json, requests, io
from pprint import pprint
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_dance.contrib.twitter import make_twitter_blueprint, twitter
from flask_dance.contrib.google import make_google_blueprint, google
from dotenv import load_dotenv



load_dotenv()

google_client_id = os.environ.get("GOOGLE_API_KEY")
google_client_secret = os.environ.get("GOOGLE_SECRET_KEY")
twitter_api_key = os.environ.get("TWITTER_API_KEY")
twitter_secret_key = os.environ.get("TWITTER_SECRET_KEY")
gmail_noreply = os.environ.get("GMAIL")
gmail_password = os.environ.get("GMAIL_PASSWORD")
aws_bucket = os.environ.get("BUCKET_NAME")

application = Flask(__name__)
application.config['SECRET_KEY'] = "CC2021"
application.secret_key = "CC2021"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] ='1'
twitter_blueprint = make_twitter_blueprint(api_key=twitter_api_key, api_secret=twitter_secret_key)
google_blueprint = make_google_blueprint(client_id=google_client_id, client_secret=google_client_secret, scope=["profile", "email"])

application.register_blueprint(twitter_blueprint, url_prefix='/twitter_login')
application.register_blueprint(google_blueprint, url_prefix="/google_login")

mail= Mail(application)
serial=URLSafeTimedSerializer("CC2021")

application.config['MAIL_SERVER']='smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = gmail_noreply
application.config['MAIL_PASSWORD'] = gmail_password
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
mail = Mail(application)





def total(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    
    table = dynamodb.Table('anime')
    scanData = table.scan()
    data = scanData['Items']
    return len(data)

def getAnimes(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        
    table = dynamodb.Table('animelist2')
    scanData = table.scan()
    data = scanData['Items']
    i = 0
    data2 = []
    while i<10:
        data2.append(data[i])
        i+=1
            
    return data2


def getAccount(email, type, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('accounts2')
    scanData = table.scan()
    data = scanData['Items']
    emailBool = False
    for item in data:
        if item['email'] == email and item['type'] == type:
            emailBool = True
    if not emailBool:
        response = {'invalid':'invalid'}
        return response
    else:
        response = table.get_item(Key={'email':email, 'type':type})
        return response['Item']
    
def getUser(username, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('accounts2')
    scanData = table.scan()
    data = scanData['Items']
    userBool = False
    for item in data:
        if item['username'] == username:
            userBool = True
    return userBool

def getEmail(email, type, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('accounts2')
    scanData = table.scan()
    data = scanData['Items']
    emailBool = False
    for item in data:
        if item['email'] == email and item['type'] == type:
            emailBool = True
    return emailBool


def getFavorites(username, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    
    favorites = dynamodb.Table('favorites2')
    anime = dynamodb.Table('animelist4')

    response = favorites.query(
        KeyConditionExpression=Key('user').eq(username)
    )

    favorites = []
    for ani in response['Items']:
        fav = anime.get_item(Key={'anime_id':ani["animeID"]})
        fav = fav["Item"]
        favorites.append(fav)
    
    return favorites


def addUser(account, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('accounts2')
    table.put_item(Item=account)

def addAnime(anime, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('animelist4')
    table.put_item(Item=anime)
    
@application.route('/insert_anime',  methods=['GET', 'POST'])
def insert_anime():
    if request.method == "POST":
        name = request.form["animeName"]
        episodes = request.form["episodes"]
        genre = request.form["genre"]
        uploadedImage = request.files.get('uploadedimage')
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('animelist4')
        scanData = table.scan()
        data = scanData['Items']
        total = len(data) + 1
        anime1 = {
            'anime_id':str(total),
            'name':name,
            'episodes':episodes,
            'url':"https://"+aws_bucket+".s3.amazonaws.com/"+str(total)+".jpg",
            'genre':genre,
            'rating':"0",
            'totalRating':"0",
            'votes' : "0"
        }
        
        exists = False
        
        for anime in data:
            if str.lower(name) in str.lower(anime["name"]):
                exists = True
                
        if not exists:
            s3 = boto3.client('s3')
            s3Resource = boto3.resource('s3', region_name='us-east-1')
            read = uploadedImage.read()
            content1 = io.BytesIO(read)
            s3.upload_fileobj(content1, aws_bucket, str(total) + ".jpg")
            acl = s3Resource.ObjectAcl(aws_bucket, str(total) + ".jpg")
            acl.put(ACL='public-read')
            addAnime(anime1)
            session["successful"] = True
        else:
            session['exists'] = True
        return redirect(url_for("insert_anime"))
    if "successful" in session:
        session.pop("successful", None)
        return render_template('insert_anime.html', successful=True) 
    if "exists" in session:
        session.pop("exists", None)
        return render_template('insert_anime.html', exists=True) 
    return render_template('insert_anime.html')
    
@application.route('/twitter')
def twitter_login():
    if not twitter.authorized:
        return redirect(url_for('twitter.login'))
    twitter_account = twitter.get('account/verify_credentials.json?include_email=true')
    if twitter_account.ok:
        account_info = twitter_account.json()
        twitterUsername = "@"+ account_info["screen_name"]
        twitterEmail = account_info["email"]
        user = getEmail(twitterEmail, "twitter")
        if not user:
            account = {
                    'email':twitterEmail,
                    'type':"twitter",
                    'username':twitterUsername,
                    'password':"N/A",
                    'verified':"true"
                }
            addUser(account)
        session["email"] = account_info["email"]
        session["type"] = "twitter"
        session["username"] = twitterUsername
    return redirect(url_for("index"))

@application.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    google_account = google.get("/oauth2/v2/userinfo")
    
    if google_account.ok:
        account_info = google_account.json()
        googleName = "G:"+ account_info["name"]
        googleEmail = account_info["email"]
        user = getEmail(googleEmail, "google")
        if not user:
            account = {
                    'email':googleEmail,
                    'type':"google",
                    'username':googleName,
                    'password':"N/A",
                    'verified':"true"
                }
            addUser(account)
        session["email"] = account_info["email"]
        session["type"] = "google"
        session["username"] = googleName
    return redirect(url_for("index"))

@application.route('/')
def index():
    top = getTopAnime()
    if "twitter_oauth_token" in session and "twitterLogged" not in session:
        session["twitterLogged"] = True
        return redirect(url_for("twitter_login"))
    if "google_oauth_token" in session and "googleLogged" not in session:
        session["googleLogged"] = True
        return redirect(url_for("google_login"))
    if "username" in session:
        return render_template('index.html', user=True, username = session["username"], top=top, length=len(top))
    return render_template('index.html', top=top, length=len(top))


def changePassword(oldPW, newPW, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('accounts2')
    
    try:
        response = table.get_item(Key={'email': session["email"], 'type':"email"})
    except ClientError as e:
        print(e.response['Error']['Message'])
        return False

    if "Item" in response and response["Item"]["password"] == oldPW:
        print(response["Item"])
        table.update_item(
            Key={
                'email': session["email"], 'type':"email"
            },
            UpdateExpression="set password=:p",
            ExpressionAttributeValues={
                ':p': newPW
            },
            ReturnValues="UPDATED_NEW"
        )
        return response
    else:
        return False

def ratingSort(e):
    return e["rating"]

def getTopAnime(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

    table = dynamodb.Table('animelist4')
    data = table.scan()
    results = []

    for anime in data['Items']:
        if float(anime["totalRating"]) > 0:
            results.append(anime)

    results.sort(key=ratingSort, reverse=True)

    return results[:10]



@application.route('/account',  methods=['GET', 'POST'])
def account():

    if "username" in session:
        favorites = getFavorites(session["username"])

        if request.method == "POST":
            if changePassword(request.form.get('old'), request.form.get('new')) == False:
                #old password does not match, so pw doesnt change
                return render_template('profile.html', favorites=favorites,
                message="Old password needs to match current password.", type=session["type"])
            else:
                #password is successfully changed
                return render_template('profile.html', favorites=favorites,
                message="Password was successfully changed.", type=session["type"])

        else:
            return render_template('profile.html', favorites=favorites, type=session["type"])
    else:
        return render_template('index.html')




@application.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        confirmPass = request.form["confirmPassword"]
        userExists = getUser(username)
        if username[0] == "@" or (username[0]=="G" and username[1]==":"):
            return render_template('register.html', invalidUsername=True) 
        if confirmPass != password:
            return render_template('register.html', passwordsNoMatch=True) 
        if userExists:
            return render_template('register.html', userExists=True) 
        response = getAccount(email, "email")
        if "invalid" in response:
            if "emailexists" in session:
                session.pop("emailexists", None)
            account = {
                'email':email,
                'type':"email",
                'username':username,
                'password':password,
                'verified':"false"
            }
            
            token = serial.dumps(email, salt="confirmation")
            
            msg = Message('Verify Account', sender = 'noreplycca3@gmail.com', recipients = [email])
            url = url_for("verifyemail", token=token, _external=True)
            msg.body = "Please verify your email by clicking this link: {}".format(url)
            mail.send(msg)
            addUser(account)
        else:
            session["emailexists"] = True
            return redirect(url_for("register"))
        session["success"] = True        
        return redirect(url_for("login"))
    else:
        if "user" in session:
            return redirect(url_for("index"))
        else:
            if "emailexists" in session:
                session.pop("emailexists", None)
                return render_template('register.html', emailexists=True) 
            return render_template('register.html')
        
@application.route('/verifyemail/<token>')
def verifyemail(token):
    try:
        
        email = serial.loads(token, salt="confirmation", max_age=3600)
        
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('accounts2')
        table.update_item(
            Key={
                'email': email,
                'type':"email"
            },
            UpdateExpression="set verified=:v",
            ExpressionAttributeValues={
                ':v': "true"
            }
        )
        session['verified'] = True
        return redirect(url_for("login"))
    except SignatureExpired:
        email = serial.loads(token, salt="confirmation")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('accounts2')
        table.delete_item(
            Key={
                'email': email
            }
        )
        session['expired'] = True
        return redirect(url_for("login"))
    
@application.route('/resetpassword/<token>', methods=["POST", "GET"])
def resetpassword(token):
    try:
        email = serial.loads(token, salt="confirmation", max_age=3600)
        session['changePassword'] = email
        return redirect(url_for("forgotpassword"))
    except SignatureExpired:
        email = serial.loads(token, salt="confirmation")
        session['expired'] = True
        return redirect(url_for("forgotpassword"))
    
@application.route('/forgotpassword', methods=["POST", "GET"])
def forgotpassword():
    if "changePassword" in session:
        email = session["changePassword"]
        session.pop("changePassword", None)
        return render_template('forgotpassword.html', changePassword=email)
    if request.method == "POST":
        if "changePassword" in request.form:
            email = request.form["changePassword"]
            password = request.form["password"]
            confirmPass = request.form["confirmPassword"]
            if confirmPass != password:
                return render_template('forgotpassword.html', changePassword=email, passwordsNoMatch=True)
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('accounts2')
            table.update_item(
                Key={
                    'email': email,
                    'type':"email"
                },
                UpdateExpression="set password=:p",
                ExpressionAttributeValues={
                    ':p': password
                }
            )
            session["passwordSuccess"] = True
            return redirect(url_for("login"))
        email = request.form["email"]
        response = getAccount(email, "email" )
        if "invalid" in response:
            session["invalid"] = True
            return redirect(url_for("forgotpassword"))
        else:
            token2 = serial.dumps(email, salt="confirmation")
            msg = Message('Change Password', sender = 'noreplycca3@gmail.com', recipients = [email])
            url = url_for("resetpassword", token=token2, _external=True)
            msg.body = "Please click this link to change password: {}".format(url)
            mail.send(msg)
            session["success"] = True
            return redirect(url_for("forgotpassword"))
    else:
        if "invalid" in session:
            session.pop("invalid", None)
            return render_template('forgotpassword.html', invalid=True)
        elif "success" in session:
            session.pop("success", None)
            return render_template('forgotpassword.html', success=True)
        elif "expired" in session:
            session.pop("expired", None)
            return render_template('forgotpassword.html', expired=True)
            
    return render_template('forgotpassword.html')

@application.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        response = getAccount(email, "email")
        if "invalid" in response:
            session["invalid"] = True
            return redirect(url_for("login"))  
        elif response['password'] == password:
            if response["verified"] == "false":
                session["verifiedNot"] = True
                return redirect(url_for("login"))   
            session["email"] = response['email']
            session["type"] = "email"
            session["username"] = response['username']
            if "invalid" in session:
                session.pop("invalid", None)
        else:
            session["invalid"] = True
            return redirect(url_for("login"))           
        return redirect(url_for("index"))
    else:
        if "username" in session:
            return redirect(url_for("index"))
        else:
            if "invalid" in session:
                session.pop("invalid", None)
                return render_template('login.html', invalid=True)
            elif "success" in session:
                session.pop("success", None)
                return render_template('login.html', success=True)
            elif "verifiedNot" in session:
                session.pop("verifiedNot", None)
                return render_template('login.html', verifiedNot=True)
            elif "verified" in session:
                session.pop("verified", None)
                return render_template('login.html', verified=True)
            elif "expired" in session:
                session.pop("expired", None)
                return render_template('login.html', expired=True)   
            elif "passwordSuccess" in session:
                session.pop("passwordSuccess", None)
                return render_template('login.html', passwordSuccess=True)                             
            return render_template('login.html')
        
@application.route('/search')
def search():
    if 'short' in session:
        session.pop('short', None)
        return render_template('search.html', short=True)
    if 'invalidResults' in session:
        session.pop('invalidResults', None)
        return render_template('search.html', invalidResults=True)
    if 'results' in session:
        results = session['results']
        session.pop("results", None)
        return render_template('search.html', results=results)
    return render_template('search.html')

@application.route('/searching', methods=["POST", "GET"])
def searching():
    if request.method == "POST":
        title = request.form["title"]
        if len(title) < 3:
            session["short"] = True
            return redirect(url_for("search"))
            
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('animelist4')
        scanData = table.scan()
        data = scanData['Items']
        results = []
        for anime in data:
            if str.lower(title) in str.lower(anime["name"]):
                results.append(anime)

        if len(results) != 0:
            session["results"] = results
        else:
            session["invalidResults"] = True
    return redirect(url_for("search"))

@application.route('/favorite', methods=["POST","GET"])
def favorite():
    if request.method == "POST":
        username = session["username"]
        anime_id = request.form["id"]
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('favorites2')
        response = table.put_item(
        Item={
                'user': username,
                'animeID': anime_id
            }
        )
    return redirect(url_for("account"))
        

@application.route('/rating', methods=["POST", "GET"])
def rating():
    if request.method == "POST":
        rate = request.form["rate"]
        anime_id = request.form["id"]
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('animelist4')
        result = table.get_item(Key={'anime_id':anime_id})
        result = result["Item"]
        votes = result["votes"]
        totalVotes = int(votes) + 1
        totalRating = int(result["totalRating"]) + int(rate)
        table.update_item(
            Key={
                'anime_id': anime_id,
            },
            UpdateExpression="set totalRating=:tr, votes=:v",
            ExpressionAttributeValues={
                ':tr': str(totalRating),
                ':v': str(totalVotes),
            },
        )
    return redirect(url_for("search"))

@application.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == '__main__':
    #application.run(host='127.0.0.1', port=8080, debug=True)
    #application.run(debug=True)
    application.run()


