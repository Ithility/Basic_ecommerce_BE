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
    email = db.Column(db.String(120), unique=True, nullable=False)
    shipping_addresses = db.relationship('ShippingAddress', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username


class ShippingAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return '<ShippingAddress %r>' % self.id


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return '<Order %r>' % self.id


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return '<OrderItem %r>' % self.id

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=True)

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


@app.route('/cart/add', methods=['POST'])
@requires_auth
def add_to_cart():
    data = request.get_json()
    user_id = data.get('user_id')
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    # Check if the product exists
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    # Check if the item is already in the cart
    existing_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if existing_item:
        # If the item already exists, update the quantity
        existing_item.quantity += quantity
    else:
        # If the item does not exist, create a new cart item
        new_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(new_item)

    db.session.commit()

    return jsonify({'message': 'Item added to cart successfully'}), 201


@app.route('/cart/update', methods=['PUT'])
@requires_auth
def update_cart():
    data = request.get_json()
    user_id = data.get('user_id')
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    # Check if the item is in the cart
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if not cart_item:
        return jsonify({'message': 'Item not found in cart'}), 404

    # Update the quantity of the item
    cart_item.quantity = quantity
    db.session.commit()

    return jsonify({'message': 'Cart updated successfully'}), 200


@app.route('/cart/remove', methods=['DELETE'])
@requires_auth
def remove_from_cart():
    data = request.get_json()
    user_id = data.get('user_id')
    product_id = data.get('product_id')

    # Check if the item is in the cart
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if not cart_item:
        return jsonify({'message': 'Item not found in cart'}), 404

    # Remove the item from the cart
    db.session.delete(cart_item)
    db.session.commit()

    return jsonify({'message': 'Item removed from cart successfully'}), 200


@app.route('/products', methods=['GET'])
def get_products():
    # Get query parameters
    name = request.args.get('name')
    category = request.args.get('category')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')

    # Start building the base query
    query = Product.query

    # Apply filters based on query parameters
    if name:
        query = query.filter(Product.name.ilike(f'%{name}%'))

    if category:
        query = query.filter(Product.category.ilike(f'%{category}%'))

    if min_price:
        query = query.filter(Product.price >= min_price)

    if max_price:
        query = query.filter(Product.price <= max_price)

    # Execute the query
    products = query.all()

    # Serialize the products to JSON
    serialized_products = [{
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'quantity': product.quantity
    } for product in products]

    return jsonify({'products': serialized_products})


@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    serialized_product = {
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'quantity': product.quantity
    }

    return jsonify(serialized_product)

@app.route('/profile', methods=['GET'])
@requires_auth
def get_profile():
    user_id = request.authorization.username
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    profile_data = {
        'username': user.username,
        'email': user.email
    }
    return jsonify(profile_data)


@app.route('/profile', methods=['PUT'])
@requires_auth
def update_profile():
    user_id = request.authorization.username
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)

    db.session.commit()
    return jsonify({'message': 'Profile updated successfully'})


@app.route('/shipping_addresses', methods=['GET'])
@requires_auth
def get_shipping_addresses():
    user_id = request.authorization.username
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    addresses = [{
        'id': address.id,
        'address': address.address,
        'city': address.city,
        'state': address.state,
        'postal_code': address.postal_code
    } for address in user.shipping_addresses]

    return jsonify(addresses)


@app.route('/shipping_addresses', methods=['POST'])
@requires_auth
def add_shipping_address():
    user_id = request.authorization.username
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    address = ShippingAddress(
        user_id=user_id,
        address=data.get('address'),
        city=data.get('city'),
        state=data.get('state'),
        postal_code=data.get('postal_code')
    )
    db.session.add(address)
    db.session.commit()

    return jsonify({'message': 'Shipping address added successfully'}), 201


@app.route('/orders', methods=['GET'])
@requires_auth
def get_orders():
    user_id = request.authorization.username
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    orders = [{
        'id': order.id,
        'order_date': order.order_date,
        'total_amount': order.total_amount,
        'items': [{
            'product_id': item.product_id,
            'quantity': item.quantity,
            'price': item.price
        } for item in order.order_items]
    } for order in user.orders]

    return jsonify(orders)


if __name__ == '__main__':
    app.run(debug=True)




