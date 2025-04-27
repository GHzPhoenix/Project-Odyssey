# Travel Odyssey Backend (Flask + PostgreSQL)
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins="http://127.0.0.1:5500")
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET")
jwt = JWTManager(app)

# PostgreSQL connection
conn = psycopg2.connect(
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT"),
    sslmode='require'
)
cursor = conn.cursor()

@app.route("/", methods=["GET"])
def home():
    return "Travel Odyssey Flask Backend is running ✅"

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    try:
        cursor.execute("""
            INSERT INTO users (name, email, password) VALUES (%s, %s, %s) RETURNING id, name, email
        """, (data['name'], data['email'], hashed))
        conn.commit()
        user = cursor.fetchone()
        return jsonify({"user": {"id": user[0], "name": user[1], "email": user[2]}}), 201
    except Exception as e:
        print("REGISTRATION ERROR:", e)
        return jsonify({"error": "Registration failed"}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    cursor.execute("SELECT * FROM users WHERE email = %s", (data['email'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not bcrypt.check_password_hash(user[3], data['password']):
        return jsonify({"error": "Invalid password"}), 401

    token = create_access_token(identity=user[0])
    return jsonify({"token": token})

@app.route("/api/bookings", methods=["POST"])
@jwt_required()
def add_booking():
    user_id = get_jwt_identity()
    data = request.json
    try:
        cursor.execute("""
            INSERT INTO bookings (user_id, destination, checkin_date, checkout_date, guests)
            VALUES (%s, %s, %s, %s, %s) RETURNING *
        """, (user_id, data['destination'], data['checkin_date'], data['checkout_date'], data['guests']))
        conn.commit()
        booking = cursor.fetchone()
        return jsonify(booking), 201
    except Exception as e:
        print("BOOKING ERROR:", e)
        return jsonify({"error": "Booking failed"}), 500

@app.route("/api/bookings", methods=["GET"])
@jwt_required()
def get_bookings():
    user_id = get_jwt_identity()
    try:
        cursor.execute("SELECT * FROM bookings WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        bookings = cursor.fetchall()
        return jsonify(bookings)
    except Exception as e:
        print("FETCH BOOKINGS ERROR:", e)
        return jsonify({"error": "Fetching failed"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
