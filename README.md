BASIC_ECOMMERCE_BE

This project is a simple backend for an e-commerce website developed using Flask, a lightweight web framework in Python.

Features:
Product Management: CRUD operations for managing products.
Authentication: Basic authentication for protecting routes.
Secure Database: SQLite database integration with SQLAlchemy ORM.
RESTful API: HTTP endpoints for creating, reading, updating, and deleting products.

Getting Started:

1.
-Clone the repository

git clone https://github.com/Ithility/Basic_ecommerce_BE

2.
-Install Dependencies:

pip install Flask Flask-SQLAlchemy

3.
-Run the application:

python main_ecommerce.py


API Endpoints
POST /product: Create a new product.
GET /product/<product_id>: Retrieve information about a specific product.
PUT /product/<product_id>: Update an existing product.
DELETE /product/<product_id>: Delete a product.


Authentication
To access the protected routes (product management), you need to provide basic authentication credentials. By default, the credentials are:

Username: admin
Password: password
Contributing
Contributions are welcome! Feel free to open issues and pull requests to suggest improvements or report bugs.

License
This project is licensed under the MIT License.
