from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
import datetime
from flask_mysqldb import MySQL
import stripe
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'root'
# app.config['MYSQL_DB'] = 'mydb2'

app.config['MYSQL_HOST'] = 'database-1.czecpljk7iqw.us-west-1.rds.amazonaws.com'
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'XNhope1010'
app.config['MYSQL_DB'] = 'mydb2'

mysql = MySQL(app)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'Clerk Xu'  # Change this!
jwt = JWTManager(app)
CORS(app)

stripe_keys = {
    "secret_key": "sk_test_51H73ZHLcoplQnnQX8k5nKXxl16G2PX9mXz5ZW55yhifLuHqmR4GzE9AOs3cDJGckzDvhD8ZwQtG6yTGBHrHMa0S6009ACt3GmJ",
    "publishable_key": "pk_test_51H73ZHLcoplQnnQXCWnzF3lk7ndlTF2ZBeJEcRDtNjZxgRNUhqULLRTJdgoiibUSmytBBS4ddWsDx7MNgno5HemT00BiEESHiN",
    "endpoint_secret": "whsec_8s86xkK7HQHS3fy29VCXPlRsHmIKtOv3"
}

stripe.api_key = stripe_keys["secret_key"]


@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 400
    username = request.json.get('username', None)
    if not username:
        return jsonify(msg="Missing username parameter"), 400
    password = request.json.get('password', None)
    if not password:
        return jsonify(msg="Missing password parameter"), 400
    first_name = request.json.get('first_name', None)
    last_name = request.json.get('last_name', None)
    email = request.json.get('email', None)
    if not email:
        return jsonify(msg="Missing email parameter"), 400

    hashed_password = generate_password_hash(password)

    cur = mysql.connection.cursor()

    cur.execute('SELECT username from user where username = "' + username + '"')
    data = cur.fetchall()
    if len(data) != 0:
        return jsonify(msg="username already exist"), 400
    cur.execute('SELECT email from user where email = "' + email + '"')
    data = cur.fetchall()
    if len(data) != 0:
        return jsonify(msg="email already exist"), 400

    cur.execute(
        "INSERT INTO user (username,password,first_name,last_name, email)"
        "VALUES(%s, %s, %s, %s, %s)",
        (username, hashed_password, first_name, last_name, email))
    mysql.connection.commit()
    # mysql.connection.close()
    return jsonify(msg='success'), 200


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify(msg="Missing username parameter"), 400
    if not password:
        return jsonify(msg="Missing password parameter"), 400

    cur = mysql.connection.cursor()
    cur.execute('SELECT * from user where username = "' + username + '"')
    data = cur.fetchall()
    if len(data) == 0:
        return jsonify(msg="username not exist"), 400

    if not check_password_hash(data[0][2], password):
        return jsonify(msg="wrong password"), 400
    user_id = data[0][0]
    first_name = data[0][3]
    last_name = data[0][4]
    email = data[0][5]
    quota_purchased = data[0][6]
    quota_used = data[0][7]
    # Identity can be any data that is json serializable
    # access_token = create_access_token(identity=username)
    # return jsonify(access_token=access_token), 200
    expires = datetime.timedelta(weeks=4)
    token = create_access_token(user_id, expires_delta=expires)
    return jsonify({'token': token, 'username': username, 'first_name': first_name,
                    'last_name': last_name, 'email': email, 'quota_purchased': quota_purchased,
                    'quota_used': quota_used}), 201


# Using the expired_token_loader decorator, we will now call
# this function whenever an expired but otherwise valid access
# token attempts to access an endpoint
@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'The {} token has expired'.format(token_type)
    }), 401


@app.route("/upload", methods=['POST'])
@jwt_required
def quota():
    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify(msg='No file key'), 400
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify(msg='No selected file'), 400
    user_id = str(get_jwt_identity())
    cur = mysql.connection.cursor()
    cur.execute('SELECT quota_purchased, quota_used from user where id ='+user_id)
    data = cur.fetchone()
    if data[0] == data[1]:
        return jsonify(msg="No quota left"), 400
    cur.execute("INSERT INTO consumption (user_id,quota_number)"
                "VALUES(%s, %s)",
                (user_id, str(1)))
    cur.execute('UPDATE user SET quota_used = quota_used+%s where id = %s',
                (str(1), user_id))
    mysql.connection.commit()
    return jsonify(msg="upload success"), 200


@app.route("/query", methods=['GET'])
@jwt_required
def query():
    user_id = get_jwt_identity()
    cur = mysql.connection.cursor()
    cur.execute('SELECT quota_purchased, quota_used from user where id = ' + str(user_id))
    data = cur.fetchone()
    return jsonify(quota_purchased=data[0], quota_used=data[1]), 200


@app.route("/product", methods=['GET'])
def product():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * from product')
    data = cur.fetchall()
    result = []
    for each in data:
        result.append({"id": each[0], "quota_number": each[1], "amount": each[2], "title": each[3]})
    return jsonify(result), 200


@app.route("/select", methods=['GET'])
def select():
    product_id = str(request.args.get('id'))
    cur = mysql.connection.cursor()
    cur.execute('SELECT * from product where id='+product_id)
    data = cur.fetchone()
    return jsonify(title=data[3], quota_number=data[1], amount=data[2])


@app.route("/payment", methods=['POST'])
@jwt_required
def charge():
    try:
        payment = stripe.PaymentIntent.create(
            amount=request.json.get('amount', None),
            currency="usd",
            # payment_method_types=["card"],
            payment_method=request.json.get('id', None),
            description=request.json.get('description', None),
            confirm=True
        )
        quota_number = str(request.json.get('quota_number', None))
        payment_data = payment['charges']['data'][0]
        user_id = str(get_jwt_identity())
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO payment (user_id,quota_number, amount, receipt_url, payment_method, payment_intent)"
                    "VALUES(%s, %s, %s, %s, %s, %s)",
                    (user_id, quota_number, str(request.json.get('amount', None)),
                     payment_data['receipt_url'], payment_data['payment_method'], payment_data['payment_intent']))
        cur.execute('UPDATE user SET quota_purchased = quota_purchased+%s where id = %s',
                    (quota_number, user_id))
        mysql.connection.commit()
        return jsonify(msg="Payment Successful"), 200

    except Exception as e:
        return jsonify(msg=str(e)), 403


@app.route('/all', methods=['GET'])
def public_test():
    return jsonify(msg='Welcome'), 200


# if __name__ == "__main__":
#     app.run()
