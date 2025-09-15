from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask_cors import CORS
from functools import wraps
from bson import ObjectId
import datetime
import os
import io

# Libraries for report generation
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# --- App Initialization & Configuration ---
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Using your specified secret key
app.config["MONGO_URI"] = "mongodb+srv://railmatrixsih_db_user:CSiHNEUKIInSVvv2@railmatrix.kaguhoo.mongodb.net/railmatrix?retryWrites=true&w=majority"
app.config["JWT_SECRET_KEY"] = "abcd1234efgh5678"

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

VALID_ROLES = ["Depot staff", "Senior officials"]

# --- Custom Decorator for Role-Based Access ---
def role_required(required_role):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role")
            if user_role != required_role:
                return jsonify({"msg": f"Forbidden: This action requires the '{required_role}' role."}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --- Home Route for Testing ---
@app.route("/")
def home():
    """Simple home page to verify the API is running."""
    return jsonify({
        "message": "RailMatrix Web API is running successfully!",
        "version": "1.0",
        "available_endpoints": {
            "authentication": ["/register", "/login", "/logout"],
            "depot_staff": ["/depot/inventory", "/depot/qr_generation"],
            "senior_officials": [
                "/senior/predictive_analysis",
                "/senior/vendor_performance", 
                "/senior/compliance_monitoring",
                "/senior/reports/generate"
            ]
        }
    })

# --- Authentication ---
@app.route("/register", methods=["POST", "OPTIONS"])
def register():
    """Endpoint for an admin to create initial user accounts."""
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"msg": "No JSON data provided"}), 400
            
        if not all(k in data for k in ("employee_id", "password", "role")):
            return jsonify({"msg": "EmployeeID, password, and role are required."}), 400

        if data['role'] not in VALID_ROLES:
            return jsonify({"msg": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

        if mongo.db.web_users.find_one({"employee_id": data["employee_id"]}):
            return jsonify({"msg": "User with this EmployeeID already exists."}), 409
            
        hashed_pwd = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
        user = {"employee_id": data["employee_id"], "password": hashed_pwd, "role": data["role"]}
        mongo.db.web_users.insert_one(user)
        return jsonify({"msg": f"User with EmployeeID {data['employee_id']} registered successfully."}), 201
    except Exception as e:
        return jsonify({"msg": f"Registration failed: {str(e)}"}), 500

@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    """Unified login for web users. Requires EmployeeID, password, and selected role."""
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"msg": "No JSON data provided"}), 400
            
        # Handle different field names from frontend
        employee_id = data.get("employee_id") or data.get("login.email") or data.get("loginEmail") or data.get("employeeId")
        password = data.get("password")
        role = data.get("role") or data.get("access_level") or data.get("accessLevel") or "Depot staff"
        
        # Convert role names if needed
        if role.lower() == "depot staff" or role.lower() == "depot":
            role = "Depot staff"
        elif role.lower() == "senior officials" or role.lower() == "senior":
            role = "Senior officials"
            
        if not all([employee_id, password, role]):
            return jsonify({"msg": "EmployeeID, password, and role are required"}), 400

        if role not in VALID_ROLES:
            return jsonify({"msg": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

        user = mongo.db.web_users.find_one({"employee_id": employee_id, "role": role})
        if user and bcrypt.check_password_hash(user["password"], password):
            additional_claims = {"role": role}
            access_token = create_access_token(identity=str(user["_id"]), additional_claims=additional_claims)
            
            # This tells the frontend which dashboard to load
            redirect_url = "/depot-dashboard" if role == "Depot staff" else "/senior-dashboard"
            return jsonify({
                "success": True,
                "access_token": access_token, 
                "redirect_url": redirect_url,
                "user": {
                    "employee_id": employee_id,
                    "role": role
                }
            })

        return jsonify({"success": False, "msg": "Invalid credentials or role"}), 401
    except Exception as e:
        return jsonify({"success": False, "msg": f"Login failed: {str(e)}"}), 500

@app.route("/logout", methods=["POST", "OPTIONS"])
@jwt_required()
def logout():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
    return jsonify({"msg": "Logout successful"}), 200

# --- Depot Staff Dashboard Endpoints ---
@app.route("/depot/inventory", methods=["GET", "OPTIONS"])
@role_required("Depot staff")
def depot_inventory():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
    """(Depot) Inventory tracking: Get all items."""
    items = list(mongo.db.inventory.find({}))
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@app.route("/depot/qr_generation", methods=["POST", "OPTIONS"])
@role_required("Depot staff")
def depot_qr_generation():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
    """(Depot) QR generation for new components."""
    data = request.get_json()
    if not all(k in data for k in ["component_type", "quantity", "lot_id", "vendor"]):
        return jsonify({"msg": "Missing required fields for QR generation"}), 400
    
    # Logic to generate and save QR data
    qr_record = {
        "component_type": data["component_type"],
        "quantity": data["quantity"],
        "lot_id": data["lot_id"],
        "vendor": data["vendor"],
        "generated_at": datetime.datetime.utcnow(),
        "generated_by": get_jwt_identity()
    }
    mongo.db.qr_codes.insert_one(qr_record)
    return jsonify({"msg": f"{data['quantity']} QR codes for Lot ID {data['lot_id']} generated successfully."}), 201

# --- Senior Official Dashboard Endpoints ---
@app.route("/senior/predictive_analysis", methods=["GET", "OPTIONS"])
@role_required("Senior officials")
def senior_predictive_analysis():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200
    """(Senior) Predictive analysis on component risk."""
    return jsonify({
        "predicted_risk": "High",
        "component_type": "Rail Clip",
        "confidence": 0.88,
        "risk_factors": ["High usage", "Environmental stress", "Age"],
        "model_accuracy_history": {
            "March": 0.92, 
            "April": 0.93, 
            "May": 0.94,
            "June": 0.95,
            "July": 0.93,
            "August": 0.96
        }
    }), 200

# --- Run Application ---
if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
