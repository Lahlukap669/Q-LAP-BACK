from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt  # ← ADD THIS BACK
from flask_restx import Api, Resource, fields, Namespace
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta
import os

from auth import UserManager, TrainerManager, PeriodizationManager
from decorators import role_required, ADMIN, ATHLETE, TRAINER
from utils import create_json_response, sanitize_input, log_with_unicode

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add CORS configuration
CORS(app, origins=['http://localhost:5173'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization'])

# Configuration for Unicode support
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JSON_AS_ASCII'] = False

# Initialize extensions
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
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

# Periodization models
periodization_response_model = api.model('PeriodizacijaOdgovor', {
    'PERIODIZATION_ID': fields.Integer(description='ID ciklizacije', example=1),
    'PERIODIZATION_NAME': fields.String(description='Ime ciklizacije', example='Priprava na sezono 2025'),
    'DIFFICULTY': fields.Integer(description='Težavost ciklizacije', example=3),
    'ATHLETE_NAME': fields.String(description='Ime športnika', example='Janez Novak'),
    'DATE_CREATED': fields.String(description='Datum nastanka', example='2025-01-15')
})

periodizations_list_model = api.model('SeznamPeriodizacij', {
    'message': fields.String(description='Sporočilo', example='ciklizacije uspešno pridobljene'),
    'periodizations': fields.List(fields.Nested(periodization_response_model), description='Seznam periodizacij'),
    'count': fields.Integer(description='Število periodizacij', example=5)
})

create_periodization_model = api.model('UstvariPeriodizacijo', {
    'athlete_id': fields.Integer(required=True, description='ID športnika', example=1),
    'difficulty': fields.Integer(required=True, description='Težavnost (1-7)', example=5),
    'competition_date': fields.String(required=True, description='Datum tekmovanja (YYYY-MM-DD)', example='2025-08-15'),
    'mesocycle_lengths': fields.String(required=True, description='Dolžine mezociklov (ločeno z vejico)', example='4,6,4'),
    'method_ids': fields.String(required=True, description='ID metod po mezociklih (ločeno s | in ,)', example='49,47,48|47,48,49|48,49,47'),
    'periodization_name': fields.String(required=True, description='Ime ciklizacije', example='Summer Competition Plan')
})

key_exercise_model = api.model('KljucnaVaja', {
    'method_id': fields.Integer(description='ID metode', example=47),
    'exercise_id': fields.Integer(description='ID vaje', example=123),
    'exercise_name': fields.String(description='Ime vaje', example='Bench Press'),
    'method_name': fields.String(description='Ime metode', example='Strength Training'),
    'usage_count': fields.Integer(description='Število uporab', example=5)
})
microcycle_model = api.model('Mikrocikel', {
    'id': fields.Integer(description='ID mikrocikla', example=25),
    'start_date': fields.String(description='Datum začetka', example='2025-04-01'),
    'active_rest': fields.Boolean(description='Ali je aktiven počitek', example=False)
})
mesocycle_model = api.model('Mezocikel', {
    'id': fields.Integer(description='ID mezocikla', example=15),
    'number_of_microcycles': fields.Integer(description='Število mikrociklov', example=4),
    'microcycles': fields.List(fields.Nested(microcycle_model), description='Seznam mikrociklov'),  # Added this line
    'motor_abilities': fields.List(fields.String, description='Motorične sposobnosti', example=['Strength', 'Endurance']),
    'training_methods': fields.List(fields.String, description='Metode treniranja', example=['Method A', 'Method B']),
    'method_groups': fields.List(fields.String, description='Skupine metod', example=['Group 1', 'Group 2']),
    'key_exercises': fields.List(fields.Nested(key_exercise_model), description='Ključne vaje')
})


periodization_info_model = api.model('InformacijePeriodizacije', {
    'id': fields.Integer(description='ID periodizacije', example=81),
    'name': fields.String(description='Ime periodizacije', example='Summer Competition Plan'),
    'difficulty': fields.Integer(description='Težavnost', example=5),
    'start_date': fields.String(description='Datum začetka', example='2025-04-01'),
    'end_date': fields.String(description='Datum konca', example='2025-08-15'),
    'duration_weeks': fields.Float(description='Trajanje v tednih', example=14.3),
    'mesocycles': fields.List(fields.Nested(mesocycle_model), description='Seznam mezociklov')
})

periodization_info_response_model = api.model('PeriodizacijaInformacijeOdgovor', {
    'message': fields.String(description='Sporočilo', example='Informacije o periodizaciji uspešno pridobljene'),
    'periodization_info': fields.Nested(periodization_info_model, description='Podrobne informacije o periodizaciji')
})




create_periodization_response_model = api.model('UstvariPeriodizacijoOdgovor', {
    'message': fields.String(description='Sporočilo o uspešnem ustvarjanju', example='Periodizacija uspešno ustvarjena')
})

# Method models
method_model = api.model('Metoda', {
    'id': fields.Integer(description='ID metode', example=47),
    'name': fields.String(description='Ime metode', example='Aerobic Base'),
    'description': fields.String(description='Opis metode', example='Nizka intenzivnost za aerobno bazo')
})

method_group_model = api.model('SkupinaMetod', {
    'group_name': fields.String(description='Ime skupine', example='Endurance'),
    'methods': fields.List(fields.Nested(method_model), description='Seznam metod v skupini')
})

motor_ability_model = api.model('MotoričnaSposobnost', {
    'motor_ability': fields.String(description='Ime motorične sposobnosti', example='Strength'),
    'method_groups': fields.List(fields.Nested(method_group_model), description='Skupine metod za to sposobnost')
})

methods_list_model = api.model('StrukturiraneMetode', {
    'message': fields.String(description='Sporočilo', example='Metode uspešno pridobljene'),
    'data': fields.List(fields.Nested(motor_ability_model), description='Strukturirane metode po motoričnih sposobnostih')
})


# Athlete models
athlete_response_model = api.model('SportnikOdgovor', {
    'id': fields.Integer(description='ID športnika', example=5),
    'first_name': fields.String(description='Ime', example='Ana'),
    'last_name': fields.String(description='Priimek', example='Novak'),
    'phone_number': fields.String(description='Telefon', example='+386123456789'),
    'email': fields.String(description='E-pošta', example='ana.novak@example.com'),
    'role': fields.Integer(description='Vloga (1=športnik)', example=1)
})

athletes_list_model = api.model('SeznamSportnikov', {
    'message': fields.String(description='Sporočilo', example='Športniki uspešno pridobljeni'),
    'athletes': fields.List(fields.Nested(athlete_response_model), description='Seznam razpoložljivih športnikov'),
    'count': fields.Integer(description='Število športnikov', example=3)
})

my_athletes_list_model = api.model('MojiSportniki', {
    'message': fields.String(description='Sporočilo', example='Moji športniki uspešno pridobljeni'),
    'athletes': fields.List(fields.Nested(athlete_response_model), description='Seznam dodeljenih športnikov'),
    'count': fields.Integer(description='Število dodeljenih športnikov', example=2)
})

# Add athlete models
add_athlete_request_model = api.model('DodajSportnika', {
    'athlete_id': fields.Integer(required=True, description='ID športnika za dodajanje', example=5)
})

add_athlete_response_model = api.model('DodajSportnikaOdgovor', {
    'message': fields.String(description='Sporočilo', example='Športnik uspešno dodeljen'),
    'athlete_id': fields.Integer(description='ID športnika', example=5),
    'athlete_name': fields.String(description='Ime športnika', example='Ana Novak'),
    'trainer_id': fields.Integer(description='ID trenerja', example=2)
})



exercise_info_model = api.model('InformacijeVaje', {
    'exercise_date': fields.String(description='Datum vaje', example='2025-04-01'),
    'day_of_week_number': fields.Integer(description='Številka dneva v tednu', example=1),
    'exercise_id': fields.Integer(description='ID vaje', example=123),
    'exercise_name': fields.String(description='Ime vaje', example='Bench Press'),
    'description': fields.String(description='Opis vaje', example='Lying on bench, press barbell upward'),
    'video_url': fields.String(description='URL videa', example='https://example.com/video.mp4'),
    'difficulty': fields.Integer(description='Težavnost (1-10)', example=5),
    'exercise_finished': fields.Boolean(description='Ali je vaja končana', example=False),
    'day_of_week_name': fields.String(description='Ime dneva v tednu', example='Monday')
})

method_parameters_model = api.model('ParametriMetode', {
    'sets': fields.Integer(description='Število serij', example=3),
    'repetitions': fields.Integer(description='Število ponovitev', example=10),
    'burden_percentage_of_mvc': fields.Float(description='Odstotek maksimalne prostovoljne kontrakcije', example=75.5),
    'vo2_max': fields.Float(description='VO2 Max', example=65.0),
    'hr_percentage': fields.Float(description='Odstotek maksimalne srčne frekvence', example=80.0),
    'rest_seconds': fields.Integer(description='Počitek v sekundah', example=90),
    'duration_min': fields.Integer(description='Trajanje v minutah', example=45),
    'contraction_type': fields.String(description='Tip kontrakcije', example='Concentric'),
    'tempo': fields.String(description='Tempo', example='3-1-2-1')
})

method_info_model = api.model('InformacijeMetode', {
    'method_id': fields.Integer(description='ID metode', example=47),
    'method_name': fields.String(description='Ime metode', example='Strength Training'),
    'method_group': fields.String(description='Skupina metode', example='Resistance'),
    'method_parameters': fields.Nested(method_parameters_model, description='Parametri metode'),
    'motor_ability_id': fields.Integer(description='ID motorične sposobnosti', example=1),
    'motor_ability': fields.String(description='Motorična sposobnost', example='Strength'),
    'exercises': fields.List(fields.Nested(exercise_info_model), description='Seznam vaj za to metodo')
})

microcycle_info_model = api.model('InformacijeMikrocikla', {
    'microcycle_id': fields.Integer(description='ID mikrocikla', example=589),
    'day_of_week_number': fields.Integer(description='Številka dneva v tednu (1-7)', example=1),
    'methods': fields.List(fields.Nested(method_info_model), description='Seznam metod za ta dan')
})

microcycle_info_response_model = api.model('MikrociklInformacijeOdgovor', {
    'message': fields.String(description='Sporočilo', example='Informacije o mikrociklu uspešno pridobljene'),
    'microcycle_info': fields.Nested(microcycle_info_model, description='Podrobne informacije o mikrociklu')
})



# ADD THIS - Error response model
error_response_model = api.model('NapakaOdgovor', {
    'message': fields.String(description='Sporočilo o napaki', example='Neveljavni podatki')
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
            # FIXED CODE - Convert ID to string:
            access_token = create_access_token(
                identity=str(user['id']),  # Convert to string
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
            current_user_id = int(get_jwt_identity())
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
            current_user_id = int(get_jwt_identity())
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
            current_user_id = int(get_jwt_identity())
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



@api.route('/debug/token')
class DebugToken(Resource):
    def post(self):
        """Debug endpoint to check token parsing"""
        try:
            # Get token from Authorization header manually
            auth_header = request.headers.get('Authorization')
            
            log_with_unicode(f"🔍 Raw Authorization header: {auth_header}")
            
            if not auth_header:
                return create_json_response(app, {'message': 'No Authorization header'}, 400)
            
            if not auth_header.startswith('Bearer '):
                return create_json_response(app, {'message': 'Invalid Authorization format'}, 400)
            
            token = auth_header.split(' ')[1]
            log_with_unicode(f"🔍 Extracted token: {token[:50]}...")
            
            # Try to decode manually
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            log_with_unicode(f"🔍 Decoded token: {decoded}")
            
            return create_json_response(app, {
                'message': 'Token is valid',
                'decoded': decoded
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"🔍 Token debug error: {e}")
            return create_json_response(app, {'message': f'Debug error: {str(e)}'}, 500)


#Trainer endpoints
@user_ns.route('/trainer/periodizations')
class TrainerPeriodizations(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Periodizacije uspešno pridobljene', periodizations_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Trener ni najden')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse periodizacije za trenutnega trenerja"""
        try:
            current_user_id = int(get_jwt_identity())
            
            # Verify user exists and is a trainer
            user = UserManager.get_user_by_id(current_user_id)
            if not user:
                return create_json_response(app, {'message': 'Trener ni najden'}, 404)
            
            # Get trainer's periodizations
            periodizations = TrainerManager.get_trainer_periodizations(current_user_id)
            
            return create_json_response(app, {
                'message': 'Periodizacije uspešno pridobljene',
                'periodizations': periodizations,
                'count': len(periodizations)
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju periodizacij: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju periodizacij'
            }, 500)

@user_ns.route('/trainer/search-athletes')
class TrainerSearchAthletes(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Športniki uspešno pridobljeni', athletes_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @role_required(TRAINER)
    def get(self):
        """Poišči razpoložljive športnike (ki niso dodeljeni nobenemu trenerju)"""
        try:
            # Get available athletes
            athletes = TrainerManager.search_athletes()
            
            return create_json_response(app, {
                'message': 'Športniki uspešno pridobljeni',
                'athletes': athletes,
                'count': len(athletes)
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri iskanju športnikov: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri iskanju športnikov'
            }, 500)

@user_ns.route('/trainer/my-athletes')
class TrainerMyAthletes(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Moji športniki uspešno pridobljeni', my_athletes_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Trener ni najden')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse športnike dodeljene trenutnemu trenerju"""
        try:
            current_user_id = int(get_jwt_identity())
            
            # Verify user exists and is a trainer
            user = UserManager.get_user_by_id(current_user_id)
            if not user:
                return create_json_response(app, {'message': 'Trener ni najden'}, 404)
            
            # Get trainer's athletes
            athletes = TrainerManager.get_my_athletes(current_user_id)
            
            return create_json_response(app, {
                'message': 'Moji športniki uspešno pridobljeni',
                'athletes': athletes,
                'count': len(athletes)
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju mojih športnikov: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju mojih športnikov'
            }, 500)

@user_ns.route('/trainer/add-athlete')
class TrainerAddAthlete(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(add_athlete_request_model, validate=True)
    @auth_ns.response(201, 'Športnik uspešno dodeljen', add_athlete_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Trener ali športnik ni najden')
    @auth_ns.response(409, 'Športnik je že dodeljen')
    @role_required(TRAINER)
    def post(self):
        """Dodeli športnika trenutnemu trenerju"""
        try:
            current_user_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate required fields
            if not data.get('athlete_id'):
                return create_json_response(app, {
                    'message': 'ID športnika je obvezen'
                }, 400)
            
            athlete_id = data['athlete_id']
            
            # Validate athlete_id is a positive integer
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            # Verify trainer exists
            trainer = UserManager.get_user_by_id(current_user_id)
            if not trainer:
                return create_json_response(app, {'message': 'Trener ni najden'}, 404)
            
            # Add athlete to trainer
            result = TrainerManager.add_athlete(current_user_id, athlete_id)
            
            return create_json_response(app, {
                'message': 'Športnik uspešno dodeljen',
                'athlete_id': result['athlete_id'],
                'athlete_name': result['athlete_name'],
                'trainer_id': result['trainer_id']
            }, 201)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri dodajanju športnika: {error_message}")
            
            # Handle specific error cases
            if "ne obstaja ali ni športnik" in error_message:
                return create_json_response(app, {'message': error_message}, 404)
            elif "že dodeljen" in error_message:
                return create_json_response(app, {'message': error_message}, 409)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri dodajanju športnika'
                }, 500)

@user_ns.route('/trainer/create-periodization')
class TrainerCreatePeriodization(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(create_periodization_model, validate=True)
    @auth_ns.response(201, 'Periodizacija uspešno ustvarjena', create_periodization_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Trener ali športnik ni najden')
    @role_required(TRAINER)
    def post(self):
        """Ustvari novo periodizacijo za športnika"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['athlete_id', 'difficulty', 'competition_date', 'mesocycle_lengths', 'method_ids', 'periodization_name']
            missing_fields = [field for field in required_fields if field not in data or data[field] is None]
            
            if missing_fields:
                return create_json_response(app, {
                    'message': f'Manjkajo obvezna polja: {", ".join(missing_fields)}'
                }, 400)
            
            # Extract and validate parameters
            athlete_id = data['athlete_id']
            difficulty = data['difficulty']
            competition_date = data['competition_date']
            mesocycle_lengths = data['mesocycle_lengths']
            method_ids = data['method_ids']
            periodization_name = data['periodization_name']
            
            # Basic validation
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            if not isinstance(difficulty, int) or difficulty < 1 or difficulty > 7:
                return create_json_response(app, {
                    'message': 'Težavnost mora biti med 1 in 7'
                }, 400)
            
            # Validate date format (basic check)
            if not competition_date or len(competition_date) != 10:
                return create_json_response(app, {
                    'message': 'Datum mora biti v formatu YYYY-MM-DD'
                }, 400)
            
            # Verify trainer exists
            trainer = UserManager.get_user_by_id(current_trainer_id)
            if not trainer:
                return create_json_response(app, {'message': 'Trener ni najden'}, 404)
            
            # Create periodization
            message = TrainerManager.create_periodization(
                athlete_id=athlete_id,
                trainer_id=current_trainer_id,
                difficulty=difficulty,
                competition_date=competition_date,
                mesocycle_lengths=mesocycle_lengths,
                method_ids=method_ids,
                periodization_name=periodization_name
            )
            
            return create_json_response(app, {
                'message': message
            }, 201)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri ustvarjanju periodizacije: {error_message}")
            
            # Handle specific Oracle errors
            if "ORA-" in error_message:
                return create_json_response(app, {
                    'message': 'Napaka v bazi podatkov pri ustvarjanju periodizacije'
                }, 500)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri ustvarjanju periodizacije'
                }, 500)

@user_ns.route('/trainer/methods')
class TrainerMethods(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Metode uspešno pridobljene', methods_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse metode razvrščene po motoričnih sposobnostih in skupinah"""
        try:
            # Get structured methods
            structured_methods = TrainerManager.get_methods()
            
            return create_json_response(app, {
                'message': 'Metode uspešno pridobljene',
                'data': structured_methods
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju metod: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju metod'
            }, 500)



# periodization info
@api.route('/periodization-info/<int:periodization_id>')
class PeriodizationInfo(Resource):
    @api.doc(security='Bearer')
    @api.response(200, 'Informacije o periodizaciji uspešno pridobljene', periodization_info_response_model)
    @api.response(400, 'Neveljavni ID periodizacije', error_response_model)
    @api.response(401, 'Žeton je obvezen')
    @api.response(404, 'Periodizacija ni najdena', error_response_model)
    @jwt_required()
    def get(self, periodization_id):
        """Pridobi podrobne informacije o periodizaciji (dostopno vsem uporabnikom)"""
        try:
            # Validate periodization_id
            if periodization_id <= 0:
                return create_json_response(app, {
                    'message': 'ID periodizacije mora biti pozitivno število'
                }, 400)
            
            # Get periodization info
            from auth import PeriodizationManager
            periodization_info = PeriodizationManager.get_periodization_info(periodization_id)
            
            return create_json_response(app, {
                'message': 'Informacije o periodizaciji uspešno pridobljene',
                'periodization_info': periodization_info
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju informacij o periodizaciji: {error_message}")
            
            if "ne obstaja" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri pridobivanju informacij o periodizaciji'
                }, 500)

@user_ns.route('/trainer/microcycle-info/<int:microcycle_id>/<int:day_of_week_number>')
class TrainerMicrocycleInfo(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Informacije o mikrociklu uspešno pridobljene', microcycle_info_response_model)
    @auth_ns.response(400, 'Neveljavni parametri', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Mikrocikel ni najden', error_response_model)
    @role_required(TRAINER)
    def get(self, microcycle_id, day_of_week_number):
        """Pridobi podrobne informacije o mikrociklu za določen dan (samo trenerji)"""
        try:
            # Validate parameters
            if microcycle_id <= 0:
                return create_json_response(app, {
                    'message': 'ID mikrocikla mora biti pozitivno število'
                }, 400)
            
            if day_of_week_number < 1 or day_of_week_number > 7:
                return create_json_response(app, {
                    'message': 'Številka dneva v tednu mora biti med 1 in 7'
                }, 400)
            
            # Get microcycle info
            microcycle_info = TrainerManager.get_microcycle_info(microcycle_id, day_of_week_number)
            
            return create_json_response(app, {
                'message': 'Informacije o mikrociklu uspešno pridobljene',
                'microcycle_info': microcycle_info
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju informacij o mikrociklu: {error_message}")
            
            if "ne obstaja" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri pridobivanju informacij o mikrociklu'
                }, 500)



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
