from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return 'Welcome to the User Management API!'

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

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

@app.route('/product', methods=['POST'])
@requires_auth
def create_product():
    data = request.get_json()
    new_product = Product(name=data['name'], description=data['description'], price=data['price'], quantity=data['quantity'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201

@app.route('/product/<int:product_id>', methods=['GET'])
@requires_auth
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({'name': product.name, 'description': product.description, 'price': product.price, 'quantity': product.quantity})

@app.route('/product/<int:product_id>', methods=['PUT'])
@requires_auth
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    product.name = data['name']
    product.description = data['description']
    product.price = data['price']
    product.quantity = data['quantity']
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200

@app.route('/product/<int:product_id>', methods=['DELETE'])
@requires_auth
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)

