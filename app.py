from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_restx import Api, Resource, fields, Namespace
from dotenv import load_dotenv
from datetime import timedelta
import os

from auth import UserManager
from decorators import role_required, ADMIN, ATHLETE, TRAINER
from utils import create_json_response, sanitize_input, log_with_unicode

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration for Unicode support
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JSON_AS_ASCII'] = False  # Enable Unicode in JSON responses

# Initialize extensions (REMOVED BCRYPT)
jwt = JWTManager(app)

# Setup Swagger API documentation
api = Api(
    app,
    version='1.0',
    title='Q-LAP API Dokumentacija',
    description='Q-LAP Backend API s podporo za slovenske znake',
    doc='/docs/',
    prefix='/api'
)

# Create namespaces
auth_ns = Namespace('auth', description='Avtentifikacija in avtorizacija')
user_ns = Namespace('users', description='Upravljanje uporabnikov')
admin_ns = Namespace('admin', description='Administrativne funkcije')

api.add_namespace(auth_ns)
api.add_namespace(user_ns)
api.add_namespace(admin_ns)

# Define data models for Swagger
register_model = api.model('RegistracijaUporabnika', {
    'first_name': fields.String(required=True, description='Ime', example='Janez'),
    'last_name': fields.String(required=True, description='Priimek', example='Novak'),
    'phone_number': fields.String(required=True, description='Telefonska številka', example='+386123456789'),
    'email': fields.String(required=True, description='E-poštni naslov', example='janez.novak@example.com'),
    'password': fields.String(required=True, description='Geslo (min 6 znakov)', example='VarnoGeslo123!'),
    'role': fields.Integer(required=True, description='Vloga (1=športnik, 2=trener)', example=1),
    'gdpr_consent': fields.Boolean(required=True, description='GDPR soglasje', example=True)
})

login_model = api.model('PrijavaUporabnika', {
    'email': fields.String(required=True, description='E-poštni naslov', example='janez.novak@example.com'),
    'password': fields.String(required=True, description='Geslo', example='VarnoGeslo123!')
})

user_update_model = api.model('PosodobitveniPodatki', {
    'first_name': fields.String(description='Novo ime', example='Marko'),
    'last_name': fields.String(description='Nov priimek', example='Krajnc'),
    'phone_number': fields.String(description='Nova telefonska številka', example='+386987654321'),
    'email': fields.String(description='Nov e-poštni naslov', example='marko.krajnc@example.com')
})

password_update_model = api.model('PosodobitveniGeslo', {
    'new_password': fields.String(required=True, description='Novo geslo (min 6 znakov)', example='NovoVarnoGeslo123!')
})

# JWT Authorization
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Vnesite JWT žeton v obliki: Bearer <vaš_žeton>'
    }
}

api.authorizations = authorizations

# Request/Response logging
@app.before_request
def before_request():
    log_with_unicode(f"→ {request.method} {request.path}")

@app.after_request
def after_request(response):
    log_with_unicode(f"← {request.method} {request.path} - Status: {response.status_code}")
    return response

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return create_json_response(app, {'message': 'Končna točka ni najdena'}, 404)

@app.errorhandler(500)
def internal_error(error):
    return create_json_response(app, {'message': 'Notranja napaka strežnika'}, 500)

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return create_json_response(app, {'message': 'Žeton je potekel'}, 401)

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return create_json_response(app, {'message': 'Neveljavni žeton'}, 401)

@jwt.unauthorized_loader
def missing_token_callback(error):
    return create_json_response(app, {'message': 'Žeton je obvezen'}, 401)

# Authentication endpoints
@auth_ns.route('/register')
class UserRegistration(Resource):
    @auth_ns.expect(register_model, validate=True)
    def post(self):
        """Registracija novega uporabnika"""
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['first_name', 'last_name', 'phone_number', 'email', 'password', 'role']
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            
            if missing_fields:
                return create_json_response(app, {
                    'message': f'Manjkajo obvezna polja: {", ".join(missing_fields)}'
                }, 400)
            
            # Validate role (updated for Oracle package - 1=athlete, 2=trainer)
            if data['role'] not in [ATHLETE, TRAINER]:
                return create_json_response(app, {
                    'message': 'Neveljavna vloga. Mora biti 1 (Športnik) ali 2 (Trener)'
                }, 400)
            
            # GDPR consent check
            if not data.get('gdpr_consent'):
                return create_json_response(app, {
                    'message': 'GDPR soglasje je obvezno'
                }, 400)
            
            # Validate password length (Oracle package checks min 6 chars)
            if len(data['password']) < 6:
                return create_json_response(app, {
                    'message': 'Geslo mora imeti vsaj 6 znakov'
                }, 400)
            
            # Register user using Oracle stored procedure
            user_id = UserManager.register_user(
                data['first_name'],
                data['last_name'], 
                data['phone_number'],
                data['email'],
                data['password'],  # Plain text - Oracle handles hashing
                data['role']
            )
            
            return create_json_response(app, {
                'message': 'Uporabnik uspešno registriran',
                'user_id': user_id
            }, 201)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri registraciji: {e}")
            return create_json_response(app, {'message': str(e)}, 400)

@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.expect(login_model, validate=True)
    def post(self):
        """Prijava uporabnika"""
        try:
            data = request.get_json()
            
            if not data.get('email') or not data.get('password'):
                return create_json_response(app, {
                    'message': 'E-poštni naslov in geslo sta obvezna'
                }, 400)
            
            # Authenticate user using Oracle stored procedure
            user = UserManager.login_user(data['email'], data['password'])
            
            if not user:
                return create_json_response(app, {
                    'message': 'Napačni podatki'
                }, 401)
            
            # Create JWT token
            access_token = create_access_token(
                identity=user['id'],
                additional_claims={'role': user['role']}
            )
            
            return create_json_response(app, {
                'message': 'Uspešna prijava',
                'access_token': access_token,
                'user': user
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri prijavi: {e}")
            return create_json_response(app, {'message': 'Prijava neuspešna'}, 500)

# User endpoints
@user_ns.route('/profile')
class UserProfile(Resource):
    @auth_ns.doc(security='Bearer')
    @jwt_required()
    def get(self):
        """Pridobi profil trenutnega uporabnika"""
        try:
            current_user_id = get_jwt_identity()
            user = UserManager.get_user_by_id(current_user_id)
            
            if not user:
                return create_json_response(app, {'message': 'Uporabnik ni najden'}, 404)
            
            return create_json_response(app, {'user': user}, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju profila: {e}")
            return create_json_response(app, {'message': 'Napaka pri pridobivanju profila'}, 500)

@user_ns.route('/profile/update')
class UserProfileUpdate(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(user_update_model)
    @jwt_required()
    def put(self):
        """Posodobi profil trenutnega uporabnika"""
        try:
            current_user_id = get_jwt_identity()
            data = request.get_json()
            
            if not data:
                return create_json_response(app, {'message': 'Ni podatkov za posodobitev'}, 400)
            
            # Update user using Oracle stored procedure
            success = UserManager.update_user(current_user_id, data)
            
            if success:
                # Get updated user data
                updated_user = UserManager.get_user_by_id(current_user_id)
                return create_json_response(app, {
                    'message': 'Profil uspešno posodobljen',
                    'user': updated_user
                }, 200)
            else:
                return create_json_response(app, {'message': 'Posodobitev neuspešna'}, 400)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri posodabljanju profila: {e}")
            return create_json_response(app, {'message': str(e)}, 500)

@user_ns.route('/profile/password')
class UserPasswordUpdate(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(password_update_model)
    @jwt_required()
    def put(self):
        """Posodobi geslo trenutnega uporabnika"""
        try:
            current_user_id = get_jwt_identity()
            data = request.get_json()
            
            if not data.get('new_password'):
                return create_json_response(app, {'message': 'Novo geslo je obvezno'}, 400)
            
            # Validate password length
            if len(data['new_password']) < 6:
                return create_json_response(app, {'message': 'Geslo mora imeti vsaj 6 znakov'}, 400)
            
            # Update password using Oracle stored procedure
            success = UserManager.update_user_password(current_user_id, data['new_password'])
            
            if success:
                return create_json_response(app, {
                    'message': 'Geslo uspešno posodobljeno'
                }, 200)
            else:
                return create_json_response(app, {'message': 'Posodobitev gesla neuspešna'}, 400)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri posodabljanju gesla: {e}")
            return create_json_response(app, {'message': str(e)}, 500)

# Admin endpoints
@admin_ns.route('/users')
class AdminUsers(Resource):
    @auth_ns.doc(security='Bearer')
    @role_required(ADMIN)
    def get(self):
        """Pridobi vse uporabnike (samo admin)"""
        try:
            # TODO: Implement get all users using Oracle procedures if needed
            return create_json_response(app, {
                'message': 'Administrativni dostop odobren', 
                'users': []
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri admin končni točki: {e}")
            return create_json_response(app, {'message': 'Napaka pri pridobivanju uporabnikov'}, 500)

# Health check
@api.route('/health')
class HealthCheck(Resource):
    def get(self):
        """Preveri zdravje sistema"""
        return create_json_response(app, {
            'status': 'v redu', 
            'message': 'Q-LAP API deluje'
        }, 200)

if __name__ == '__main__':
    log_with_unicode("🚀 Zaganjam Q-LAP API strežnik...")
    log_with_unicode("📚 Swagger dokumentacija: http://localhost:5000/docs/")
    log_with_unicode("🏥 Preverjanje zdravja: http://localhost:5000/api/health")
    app.run(debug=True, host='0.0.0.0', port=5000)
