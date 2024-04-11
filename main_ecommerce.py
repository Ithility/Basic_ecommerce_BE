from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask import Flask, request, jsonify
import bcrypt
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Product %r>' % self.name


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<CartItem %r>' % self.id


def generate_hashed_password(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    hashed_input_password = bcrypt.hashpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    return hashed_input_password == hashed_password


def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(payload, 'secret_key', algorithm='HS256')
    return token.decode('utf-8')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def check_auth(username, password):
    return username == 'admin' and password == 'password'

# Routes

@app.route('/')
def index():
    return 'Welcome to the User Management API!'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 409


    hashed_password = generate_hashed_password(password)


    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'message': 'Invalid username or password'}), 401


    token = generate_token(user.id)
    return jsonify({'token': token}), 200

# Product routes...

# Cart routes
@app.route('/cart', methods=['POST'])
@requires_auth
def add_to_cart():
    data = request.get_json()
    user_id = data.get('user_id')
    product_id = data.get('product_id')
    quantity = data.get('quantity')


    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404


    existing_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if existing_item:

        existing_item.quantity += quantity
    else:

        new_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(new_item)

    db.session.commit()

    return jsonify({'message': 'Item added to cart successfully'}), 201

@app.route('/cart/<int:user_id>', methods=['GET'])
@requires_auth
def view_cart(user_id):

    cart_items = CartItem.query.filter_by(user_id=user_id).all()

    cart = []
    for item in cart_items:
        product = Product.query.get(item.product_id)
        cart.append({'product_id': item.product_id, 'name': product.name, 'quantity': item.quantity})

    return jsonify({'cart': cart})

@app.route('/cart/<int:user_id>/<int:product_id>', methods=['DELETE'])
@requires_auth
def remove_from_cart(user_id, product_id):

    item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if not item:
        return jsonify({'message': 'Item not found in cart'}), 404

    db.session.delete(item)
    db.session.commit()

    return jsonify({'message': 'Item removed from cart successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)



