from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from functools import wraps
from bson import ObjectId
import datetime
import os
import io

# Libraries for report generation
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
# from docx import Document  # Commented out to avoid import error

# --- App Initialization & Configuration ---
app = Flask(__name__)

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
@app.route("/register", methods=["POST"])
def register():
    """Endpoint for an admin to create initial user accounts."""
    data = request.get_json()
    if not data or not all(k in data for k in ("employee_id", "password", "role")):
        return jsonify({"msg": "EmployeeID, password, and role are required."}), 400

    if data['role'] not in VALID_ROLES:
        return jsonify({"msg": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

    if mongo.db.web_users.find_one({"employee_id": data["employee_id"]}):
        return jsonify({"msg": "User with this EmployeeID already exists."}), 409
        
    hashed_pwd = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    user = {"employee_id": data["employee_id"], "password": hashed_pwd, "role": data["role"]}
    mongo.db.web_users.insert_one(user)
    return jsonify({"msg": f"User with EmployeeID {data['employee_id']} registered successfully."}), 201

@app.route("/login", methods=["POST"])
def login():
    """Unified login for web users. Requires EmployeeID, password, and selected role."""
    data = request.get_json()
    if not data or not all(k in data for k in ("employee_id", "password", "role")):
        return jsonify({"msg": "EmployeeID, password, and role are required"}), 400

    role = data.get("role")
    if role not in VALID_ROLES:
        return jsonify({"msg": f"Invalid role. Choose from: {VALID_ROLES}"}), 400

    user = mongo.db.web_users.find_one({"employee_id": data["employee_id"], "role": role})
    if user and bcrypt.check_password_hash(user["password"], data["password"]):
        additional_claims = {"role": role}
        access_token = create_access_token(identity=str(user["_id"]), additional_claims=additional_claims)
        
        # This tells the frontend which dashboard to load
        redirect_url = "/depot-dashboard" if role == "Depot staff" else "/senior-dashboard"
        return jsonify(access_token=access_token, redirect_url=redirect_url)

    return jsonify({"msg": "Invalid credentials or role"}), 401

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    # For a stateless logout, the frontend just needs to delete the token.
    # For a stateful one, you would add the token's JTI to a blocklist here.
    return jsonify({"msg": "Logout successful"}), 200

# --- Depot Staff Dashboard Endpoints ---
@app.route("/depot/inventory", methods=["GET"])
@role_required("Depot staff")
def depot_inventory():
    """(Depot) Inventory tracking: Get all items."""
    items = list(mongo.db.inventory.find({}))
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify(items), 200

@app.route("/depot/qr_generation", methods=["POST"])
@role_required("Depot staff")
def depot_qr_generation():
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

@app.route("/depot/dispatch", methods=["GET"])
@role_required("Depot staff")
def depot_dispatch():
    """(Depot) Dispatch management."""
    dispatches = list(mongo.db.dispatches.find({}))
    for dispatch in dispatches:
        dispatch["_id"] = str(dispatch["_id"])
    return jsonify(dispatches), 200

@app.route("/depot/vendor_verification", methods=["POST"])
@role_required("Depot staff")
def depot_vendor_verification():
    """(Depot) Vendor lot verification."""
    data = request.get_json()
    if not all(k in data for k in ["vendor_name", "lot_id", "verification_status"]):
        return jsonify({"msg": "Missing required fields for vendor verification"}), 400
    
    verification_record = {
        "vendor_name": data["vendor_name"],
        "lot_id": data["lot_id"],
        "verification_status": data["verification_status"],
        "verified_at": datetime.datetime.utcnow(),
        "verified_by": get_jwt_identity()
    }
    mongo.db.vendor_verifications.insert_one(verification_record)
    return jsonify({"msg": f"Vendor {data['vendor_name']} lot {data['lot_id']} verification completed."}), 201

@app.route("/depot/warranty_claims", methods=["GET"])
@role_required("Depot staff")
def depot_warranty_claims():
    """(Depot) Warranty claims management."""
    claims = list(mongo.db.warranty_claims.find({}))
    for claim in claims:
        claim["_id"] = str(claim["_id"])
    return jsonify(claims), 200

# --- Senior Official Dashboard Endpoints ---
@app.route("/senior/predictive_analysis", methods=["GET"])
@role_required("Senior officials")
def senior_predictive_analysis():
    """(Senior) Predictive analysis on component risk."""
    # In a real app, this would call a machine learning model
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

@app.route("/senior/vendor_performance", methods=["GET"])
@role_required("Senior officials")
def senior_vendor_performance():
    """(Senior) Vendor performance benchmarking."""
    # Data fetched and aggregated from dispatch and quality logs
    return jsonify([
        {
            "vendor": "Vendor A", 
            "reliability": 99.5, 
            "on_time_delivery": 98.2, 
            "quality_score": 4.9, 
            "cost_efficiency": "Excellent",
            "total_orders": 245,
            "defect_rate": 0.8
        },
        {
            "vendor": "Vendor B", 
            "reliability": 95.1, 
            "on_time_delivery": 91.5, 
            "quality_score": 4.5, 
            "cost_efficiency": "Good",
            "total_orders": 189,
            "defect_rate": 2.3
        }
    ]), 200

@app.route("/senior/compliance_monitoring", methods=["GET"])
@role_required("Senior officials")
def senior_compliance_monitoring():
    """(Senior) Compliance monitoring for certifications."""
    # Data fetched from a vendor certifications collection
    return jsonify({
        "Vendor A": {
            "iso_9001": "Active", 
            "safety_2025": "Active",
            "quality_cert": "Active",
            "environmental_cert": "Pending"
        },
        "Vendor B": {
            "iso_9001": "Active", 
            "safety_2025": "Expired",
            "quality_cert": "Active",
            "environmental_cert": "Active"
        }
    }), 200

# --- Advanced Report Generation Endpoint ---
@app.route("/senior/reports/generate", methods=["GET"])
@role_required("Senior officials")
def generate_report():
    """(Senior) Generates and exports various audit reports."""
    report_type = request.args.get('type', 'generic') # e.g., ?type=safety_audit
    export_format = request.args.get('export') # e.g., &export=excel

    # Fetch data for the report from the database (using mock data here)
    mock_data = [
        {"id": 1, "type": "Safety Audit", "date": "2025-09-01", "result": "Pass", "notes": "All checks clear."},
        {"id": 2, "type": "Inspection Log", "date": "2025-09-05", "result": "Minor issues", "notes": "Found rust on 2% of clips."},
        {"id": 3, "type": "Performance Trend", "date": "2025-09-10", "result": "Stable", "notes": "Vendor A performance remains high."},
        {"id": 4, "type": "Compliance Summary", "date": "2025-09-12", "result": "Pass", "notes": "All vendors compliant."},
        {"id": 5, "type": "Quality Metrics", "date": "2025-09-14", "result": "Good", "notes": "Quality scores improved by 5%."}
    ]

    if not export_format:
        # Default action: return JSON data
        return jsonify(mock_data), 200

    if export_format == 'excel':
        # Return CSV format instead of Excel
        csv_content = "id,type,date,result,notes\n"
        for row in mock_data:
            csv_content += f"{row['id']},{row['type']},{row['date']},{row['result']},{row['notes']}\n"
        return csv_content, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=report.csv'}

    elif export_format == 'pdf':
        output = io.BytesIO()
        p = canvas.Canvas(output, pagesize=letter)
        p.drawString(72, 800, f"{report_type.replace('_', ' ').title()} Report")
        p.drawString(72, 780, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y = 750
        for row in mock_data:
            p.drawString(72, y, f"ID: {row['id']}, Type: {row['type']}, Date: {row['date']}")
            y -= 15
            p.drawString(72, y, f"Result: {row['result']}, Notes: {row['notes']}")
            y -= 25
        p.save()
        output.seek(0)
        return send_file(output, as_attachment=True, download_name=f'{report_type}.pdf')

    return jsonify({"msg": "Invalid export format specified. Available: excel, pdf"}), 400

# --- Additional Depot Staff Endpoints for Complete Functionality ---
@app.route("/depot/udm_reports", methods=["GET"])
@role_required("Depot staff")
def depot_udm_reports():
    """(Depot) UDM reports generation."""
    report_type = request.args.get('type', 'inventory')
    
    if report_type == 'inventory':
        # Export inventory to UDM format
        inventory_data = list(mongo.db.inventory.find({}))
        for item in inventory_data:
            item["_id"] = str(item["_id"])
        return jsonify({
            "report_type": "UDM Inventory Export",
            "generated_at": datetime.datetime.utcnow(),
            "data": inventory_data
        }), 200
    
    elif report_type == 'monthly_stock':
        # Monthly stock report
        return jsonify({
            "report_type": "Monthly Stock Report",
            "month": "September 2025",
            "total_items": 1250,
            "items_dispatched": 890,
            "items_received": 340,
            "low_stock_alerts": 15
        }), 200
    
    elif report_type == 'vendor_performance':
        # Vendor performance for depot
        return jsonify({
            "report_type": "Vendor Performance Report",
            "top_performers": ["Vendor A", "Vendor C"],
            "underperformers": ["Vendor D"],
            "average_delivery_time": "5.2 days"
        }), 200
    
    else:
        return jsonify({"msg": "Invalid report type. Available: inventory, monthly_stock, vendor_performance"}), 400

# --- Run Application ---
if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
