from flask import Flask, request, jsonify, g, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt  # ← ADD THIS BACK
from flask_restx import Api, Resource, fields, Namespace
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta
import os

from auth import UserManager, TrainerManager, PeriodizationManager, AthleteManager
from decorators import role_required, ADMIN, ATHLETE, TRAINER
from utils import create_json_response, sanitize_input, log_with_unicode

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add CORS configuration
CORS(app, 
     origins=[
         'http://localhost:5173',
         'http://ulicar.si',
         'http://qlap-flaskapi.ddns.net'
     ],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],  # Include OPTIONS
     expose_headers=['Content-Type', 'Authorization'])



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

# Add this with your existing models
delete_periodization_model = api.model('IzbrisiPeriodizacijo', {
    'periodization_id': fields.Integer(required=True, description='ID periodizacije za brisanje', example=199)
})

delete_periodization_response_model = api.model('IzbrisiPeriodizacijoOdgovor', {
    'message': fields.String(description='Sporočilo o uspešnem brisanju', example='Periodizacija z ID 199 je bila uspešno izbrisana')
})

test_exercise_model = api.model('TestnaVaja', {
    'id': fields.Integer(description='ID vaje', example=123),
    'exercise': fields.String(description='Ime vaje', example='Jump Squat'),
    'description': fields.String(description='Opis vaje', example='Explosive jumping movement from squat position'),
    'video_url': fields.String(description='URL videa', example='https://example.com/jump-squat.mp4')
})

test_method_group_model = api.model('TestnaSkupinaMetod', {
    'method_group': fields.String(description='Ime skupine metod', example='Explosive Power'),
    'exercises': fields.List(fields.Nested(test_exercise_model), description='Seznam testnih vaj v skupini')
})

test_motor_ability_model = api.model('TestnaMotoričnaSposobnost', {
    'motor_ability': fields.String(description='Ime motorične sposobnosti', example='Moč'),
    'method_groups': fields.List(fields.Nested(test_method_group_model), description='Skupine metod s testnimi vajami')
})

test_exercises_list_model = api.model('SeznamTestnihVaj', {
    'message': fields.String(description='Sporočilo', example='Testne vaje uspešno pridobljene'),
    'data': fields.List(fields.Nested(test_motor_ability_model), description='Testne vaje razvrščene po motoričnih sposobnostih'),
    'total_exercises': fields.Integer(description='Skupno število testnih vaj', example=25)
})

test_exercise_input_model = api.model('TestVaja', {
    'exercise_id': fields.Integer(required=True, description='ID vaje', example=123),
    'measure': fields.Float(required=True, description='Meritev', example=50.5),
    'unit': fields.String(required=True, description='Enota meritve', example='kg')
})

create_test_model = api.model('UstvariTest', {
    'athlete_id': fields.Integer(required=True, description='ID športnika', example=1),
    'date': fields.String(required=True, description='Datum testa (YYYY-MM-DD)', example='2025-06-01'),
    'exercises': fields.List(fields.Nested(test_exercise_input_model), required=True, description='Seznam vaj za test')
})

create_test_response_model = api.model('UstvariTestOdgovor', {
    'message': fields.String(description='Sporočilo o uspešnem ustvarjanju', example='Test z ID 10 je bil uspešno ustvarjen z 3 vajami')
})


test_info_model = api.model('InformacijeTest', {
    'id': fields.Integer(description='ID testa', example=15),
    'test_date': fields.String(description='Datum testa', example='2025-06-01'),
    'athlete_first_name': fields.String(description='Ime športnika', example='Ana'),
    'athlete_last_name': fields.String(description='Priimek športnika', example='Novak'),
    'athlete_full_name': fields.String(description='Polno ime športnika', example='Ana Novak')
})

tests_list_model = api.model('SeznamTestov', {
    'message': fields.String(description='Sporočilo', example='Testi uspešno pridobljeni'),
    'tests': fields.List(fields.Nested(test_info_model), description='Seznam testov'),
    'count': fields.Integer(description='Število testov', example=5)
})

delete_test_model = api.model('IzbrisiTest', {
    'test_id': fields.Integer(required=True, description='ID testa za brisanje', example=5)
})

delete_test_response_model = api.model('IzbrisiTestOdgovor', {
    'message': fields.String(description='Sporočilo o uspešnem brisanju', example='Test z ID 5 je bil uspešno izbrisan')
})

test_exercise_analytics_model = api.model('TestVajaAnalitika', {
    'exercise': fields.String(description='Ime vaje', example='Bench Press'),
    'measure': fields.Float(description='Meritev', example=75.5),
    'unit': fields.String(description='Enota', example='kg')
})

test_analytics_model = api.model('TestAnalitika', {
    'id': fields.Integer(description='ID testa', example=5),
    'test_date': fields.String(description='Datum testa', example='05-JUN-25'),
    'exercises': fields.List(fields.Nested(test_exercise_analytics_model), description='Seznam vaj v testu')
})

get_test_analytics_by_athlete_model = api.model('PridobiTestAnalitikoPodleSportnika', {
    'athlete_id': fields.Integer(required=True, description='ID športnika za analitiko', example=25)
})

test_analytics_by_athlete_response_model = api.model('TestAnalitikaPoSportnikuOdgovor', {
    'message': fields.String(description='Sporočilo', example='Test analitika uspešno pridobljena'),
    'athlete_id': fields.Integer(description='ID športnika', example=25),
    'total_tests': fields.Integer(description='Skupno število testov', example=3),
    'tests': fields.List(fields.Nested(test_analytics_model), description='Seznam vseh testov z vajami')
})

test_motor_ability_analytics_model = api.model('TestMotoricnaSposobnostAnalitika', {
    'motor_ability': fields.String(description='Motorična sposobnost', example='Moč'),
    'measure': fields.Float(description='Normalizirana meritev (allometric scaling)', example=2.85),
    'unit': fields.String(description='Normalizirana enota', example='kg/kg^0.67'),
    'exercise_count': fields.Integer(description='Število vaj v izračunu', example=3),
    'category': fields.String(description='Kategorija normalizacije', example='strength')
})


test_motor_ability_analytics_test_model = api.model('TestMotoricneSposobnostiAnalitika', {
    'id': fields.Integer(description='ID testa', example=5),
    'test_date': fields.String(description='Datum testa', example='05-JUN-25'),
    'motor_abilities': fields.List(fields.Nested(test_motor_ability_analytics_model), description='Seznam motoričnih sposobnosti v testu')
})

get_motor_ability_analytics_model = api.model('PridobiAnalitikuMotoricnihSposobnosti', {
    'athlete_id': fields.Integer(required=True, description='ID športnika za analitiko', example=25)
})

motor_ability_analytics_response_model = api.model('MotoricneSposobnostiAnalitikaOdgovor', {
    'message': fields.String(description='Sporočilo', example='Analitika motoričnih sposobnosti uspešno pridobljena'),
    'athlete_id': fields.Integer(description='ID športnika', example=25),
    'total_tests': fields.Integer(description='Skupno število testov', example=3),
    'tests': fields.List(fields.Nested(test_motor_ability_analytics_test_model), description='Seznam vseh testov z motoričnimi sposobnostmi')
})


past_test_exercise_model = api.model('PrejšnjaTestnaVaja', {
    'exercise_id': fields.Integer(description='ID vaje', example=292),
    'unit': fields.String(description='Enota meritve', example='kg')
})

past_test_exercises_response_model = api.model('PrejšnjeTestneVajeOdgovor', {
    'message': fields.String(description='Sporočilo', example='Prejšnje testne vaje uspešno pridobljene'),
    'most_recent_test_id': fields.Integer(description='ID najnovejšega testa', example=12),
    'most_recent_test_date': fields.String(description='Datum najnovejšega testa', example='2025-04-15'),
    'exercises': fields.List(fields.Nested(past_test_exercise_model), description='Seznam vaj z enotami'),
    'found_past_test': fields.Boolean(description='Ali je bil najden prejšnji test', example=True)
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

athlete_microcycle_request_model = api.model('SportnikMikrociklInfo', {
    'current_date': fields.String(description='Trenutni datum (YYYY-MM-DD), optional - default today', example='2025-06-16')
})

athlete_microcycle_response_model = api.model('SportnikMikrociklInfoOdgovor', {
    'message': fields.String(description='Sporočilo', example='Informacije o mikrociklu uspešno pridobljene'),
    'athlete_id': fields.Integer(description='ID športnika', example=25),
    'current_date': fields.String(description='Datum', example='2025-06-16'),
    'day_of_week_number': fields.Integer(description='Številka dneva v tednu', example=1),
    'microcycle_id': fields.Integer(description='ID mikrocikla', example=589),
    'active_rest': fields.Boolean(description='Ali je aktiven počitek', example=False),
    'methods': fields.List(fields.Nested(method_info_model), description='Seznam metod za ta dan')
})

exercise_status_model = api.model('StanjeVaje', {
    'exercise_id': fields.Integer(required=True, description='ID vaje', example=123),
    'finished': fields.Boolean(required=True, description='Ali je vaja končana', example=True)
})

save_finished_exercises_model = api.model('ShraniKoncaneVaje', {
    'microcycle_id': fields.Integer(required=True, description='ID mikrocikla', example=589),
    'day_of_week_number': fields.Integer(required=True, description='Številka dneva v tednu (1-7)', example=1),
    'exercises_status': fields.List(fields.Nested(exercise_status_model), required=True, description='Seznam vaj s statusom')
})

save_finished_exercises_response_model = api.model('ShraniKoncaneVajeOdgovor', {
    'message': fields.String(description='Sporočilo o uspešnosti', example='Uspešno posodobljenih 3 vaj'),
    'updated_exercises': fields.Integer(description='Število posodobljenih vaj', example=3),
    'failed_exercises': fields.List(fields.String, description='Seznam neuspešnih posodobitev', example=[])
})

athlete_test_info_model = api.model('SportnikInformacijeTest', {
    'id': fields.Integer(description='ID testa', example=15),
    'test_date': fields.String(description='Datum testa', example='2025-06-01'),
    'trainer_full_name': fields.String(description='Polno ime trenerja', example='Marko Kovač')
})

athlete_tests_list_model = api.model('SportnikSeznamTestov', {
    'message': fields.String(description='Sporočilo', example='Testi uspešno pridobljeni'),
    'tests': fields.List(fields.Nested(athlete_test_info_model), description='Seznam testov'),
    'count': fields.Integer(description='Število testov', example=5)
})

athlete_test_analytics_response_model = api.model('SportnikTestAnalitikaOdgovor', {
    'message': fields.String(description='Sporočilo', example='Test analitika uspešno pridobljena'),
    'athlete_id': fields.Integer(description='ID športnika', example=25),
    'total_tests': fields.Integer(description='Skupno število testov', example=5),
    'tests': fields.List(fields.Nested(test_analytics_model), description='Seznam vseh testov z vajami')
})

athlete_motor_ability_analytics_response_model = api.model('SportnikMotoricneSposobnostiAnalitikaOdgovor', {
    'message': fields.String(description='Sporočilo', example='Analitika motoričnih sposobnosti uspešno pridobljena'),
    'athlete_id': fields.Integer(description='ID športnika', example=25),
    'total_tests': fields.Integer(description='Skupno število testov', example=3),
    'tests': fields.List(fields.Nested(test_motor_ability_analytics_test_model), description='Seznam vseh testov z motoričnimi sposobnostmi')
})

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
            print(f"Authorization header: {request.headers.get('Authorization')}")
            print(f"All headers: {dict(request.headers)}")
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

@user_ns.route('/trainer/delete-periodization')
class TrainerDeletePeriodization(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(delete_periodization_model, validate=True)
    @auth_ns.response(200, 'Periodizacija uspešno izbrisana', delete_periodization_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Periodizacija ni najdena', error_response_model)
    @role_required(TRAINER)
    def delete(self):
        """Izbriši periodizacijo po ID-ju (samo trener lahko briše svoje periodizacije)"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('periodization_id'):
                return create_json_response(app, {
                    'message': 'ID periodizacije je obvezen'
                }, 400)
            
            periodization_id = data['periodization_id']
            
            # Validate periodization_id is a positive integer
            if not isinstance(periodization_id, int) or periodization_id <= 0:
                return create_json_response(app, {
                    'message': 'ID periodizacije mora biti pozitivno celo število'
                }, 400)
            
            # Delete periodization
            message = TrainerManager.delete_periodization(current_trainer_id, periodization_id)
            
            return create_json_response(app, {
                'message': message
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri brisanju periodizacije: {error_message}")
            
            if "ne obstaja ali ni dodeljena" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            elif "ni bila najdena" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri brisanju periodizacije'
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


@user_ns.route('/trainer/get-past-test-exercises')
class TrainerGetPastTestExercises(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(past_test_exercise_model, validate=True)
    @auth_ns.response(200, 'Prejšnje testne vaje uspešno pridobljene', past_test_exercises_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden ali ni dodeljen trenerju')
    @role_required(TRAINER)
    def post(self):
        """Pridobi ID-je vaj iz najnovejšega testa v zadnjih 2 mesecih"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Extract data
            test_date = data.get('test_date')
            athlete_id = data.get('athlete_id')
            
            # Validate required fields
            if not test_date or not athlete_id:
                return create_json_response(app, {
                    'message': 'Datum testa in ID športnika sta obvezna'
                }, 400)
            
            # Validate athlete_id
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            # Validate date format
            if not test_date or len(test_date) != 10:
                return create_json_response(app, {
                    'message': 'Datum mora biti v formatu YYYY-MM-DD'
                }, 400)
            
            # Validate date format more thoroughly
            try:
                from datetime import datetime
                datetime.strptime(test_date, '%Y-%m-%d')
            except ValueError:
                return create_json_response(app, {
                    'message': 'Neveljaven datum. Uporabite format YYYY-MM-DD'
                }, 400)
            
            # Get past test exercises
            result = TrainerManager.get_past_test_exercises(current_trainer_id, test_date, athlete_id)
            
            if result['found_past_test']:
                message = f"Najden prejšnji test z {len(result['exercises'])} vajami"
            else:
                message = "Ni najdenega prejšnjega testa v zadnjih 2 mesecih"
            
            return create_json_response(app, {
                'message': message,
                'most_recent_test_id': result['most_recent_test_id'],
                'most_recent_test_date': result['most_recent_test_date'],
                'exercises': result['exercises'],
                'found_past_test': result['found_past_test']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri iskanju prejšnjih testnih vaj: {error_message}")
            
            if "ni dodeljen temu trenerju" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri iskanju prejšnjih testnih vaj'
                }, 500)

@user_ns.route('/trainer/delete-test')
class TrainerDeleteTest(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(delete_test_model, validate=True)
    @auth_ns.response(200, 'Test uspešno izbrisan', delete_test_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Test ni najden', error_response_model)
    @role_required(TRAINER)
    def delete(self):
        """Izbriši test po ID-ju (samo trener lahko briše svoje teste)"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('test_id'):
                return create_json_response(app, {
                    'message': 'ID testa je obvezen'
                }, 400)
            
            test_id = data['test_id']
            
            # Validate test_id is a positive integer
            if not isinstance(test_id, int) or test_id <= 0:
                return create_json_response(app, {
                    'message': 'ID testa mora biti pozitivno celo število'
                }, 400)
            
            # Delete test
            message = TrainerManager.delete_test(current_trainer_id, test_id)
            
            return create_json_response(app, {
                'message': message
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri brisanju testa: {error_message}")
            
            if "ne obstaja ali ni dodeljen" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            elif "ni bil najden" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri brisanju testa'
                }, 500)


@user_ns.route('/trainer/get-test-analytics')
class TrainerGetTestAnalytics(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(get_test_analytics_by_athlete_model, validate=True)
    @auth_ns.response(200, 'Test analitika uspešno pridobljena', test_analytics_by_athlete_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden ali ni dodeljen trenerju')
    @role_required(TRAINER)
    def post(self):
        """Pridobi analitiko vseh testov za določenega športnika"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('athlete_id'):
                return create_json_response(app, {
                    'message': 'ID športnika je obvezen'
                }, 400)
            
            athlete_id = data['athlete_id']
            
            # Validate athlete_id is a positive integer
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            # Get test analytics by athlete
            analytics = TrainerManager.get_test_analytics_by_athlete(current_trainer_id, athlete_id)
            
            return create_json_response(app, {
                'message': 'Test analitika uspešno pridobljena',
                'athlete_id': analytics['athlete_id'],
                'total_tests': analytics['total_tests'],
                'tests': analytics['tests']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju test analitike: {error_message}")
            
            if "ni dodeljen temu trenerju" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri pridobivanju test analitike'
                }, 500)

@user_ns.route('/trainer/get-motor-ability-analytics')
class TrainerGetMotorAbilityAnalytics(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(get_motor_ability_analytics_model, validate=True)
    @auth_ns.response(200, 'Analitika motoričnih sposobnosti uspešno pridobljena', motor_ability_analytics_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden ali ni dodeljen trenerju')
    @role_required(TRAINER)
    def post(self):
        """Pridobi analitiko motoričnih sposobnosti za vse teste določenega športnika"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('athlete_id'):
                return create_json_response(app, {
                    'message': 'ID športnika je obvezen'
                }, 400)
            
            athlete_id = data['athlete_id']
            
            # Validate athlete_id is a positive integer
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            # Get motor ability analytics by athlete
            analytics = TrainerManager.get_motor_ability_analytics_by_athlete(current_trainer_id, athlete_id)
            
            return create_json_response(app, {
                'message': 'Analitika motoričnih sposobnosti uspešno pridobljena',
                'athlete_id': analytics['athlete_id'],
                'total_tests': analytics['total_tests'],
                'tests': analytics['tests']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju analitike motoričnih sposobnosti: {error_message}")
            
            if "ni dodeljen temu trenerju" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri pridobivanju analitike motoričnih sposobnosti'
                }, 500)


@user_ns.route('/users/athlete/get-test-exercises')
class TrainerGetTestExercises(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Testne vaje uspešno pridobljene', test_exercises_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse testne vaje razvrščene po motoričnih sposobnostih in skupinah metod"""
        try:
            # Get structured test exercises
            structured_exercises = TrainerManager.get_test_exercises()
            
            # Count total exercises
            total_exercises = 0
            for motor_ability in structured_exercises:
                for method_group in motor_ability['method_groups']:
                    total_exercises += len(method_group['exercises'])
            
            return create_json_response(app, {
                'message': 'Testne vaje uspešno pridobljene',
                'data': structured_exercises,
                'total_exercises': total_exercises
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testnih vaj: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju testnih vaj'
            }, 500)

@user_ns.route('/users/trainer/get-test-exercises')
class TrainerGetTestExercises(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Testne vaje uspešno pridobljene', test_exercises_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse testne vaje razvrščene po motoričnih sposobnostih in skupinah metod"""
        try:
            # Get structured test exercises
            structured_exercises = TrainerManager.get_test_exercises()
            
            # Count total exercises
            total_exercises = 0
            for motor_ability in structured_exercises:
                for method_group in motor_ability['method_groups']:
                    total_exercises += len(method_group['exercises'])
            
            return create_json_response(app, {
                'message': 'Testne vaje uspešno pridobljene',
                'data': structured_exercises,
                'total_exercises': total_exercises
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testnih vaj: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju testnih vaj'
            }, 500)

@user_ns.route('/athlete/save-finished-exercises')
class AthleteSaveFinishedExercises(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(save_finished_exercises_model, validate=True)
    @auth_ns.response(200, 'Stanje vaj uspešno shranjeno', save_finished_exercises_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo športniki imajo dostop')
    @auth_ns.response(404, 'Mikrocikel ni najden ali ne pripada športniku')
    @role_required(ATHLETE)
    def post(self):
        """Shrani stanje končanih vaj za določen dan mikrocikla"""
        try:
            current_athlete_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Validate required fields
            microcycle_id = data.get('microcycle_id')
            day_of_week_number = data.get('day_of_week_number')
            exercises_status = data.get('exercises_status')
            
            if not microcycle_id or not day_of_week_number or not exercises_status:
                return create_json_response(app, {
                    'message': 'Vsi podatki (microcycle_id, day_of_week_number, exercises_status) so obvezni'
                }, 400)
            
            # Validate microcycle_id
            if not isinstance(microcycle_id, int) or microcycle_id <= 0:
                return create_json_response(app, {
                    'message': 'ID mikrocikla mora biti pozitivno celo število'
                }, 400)
            
            # Validate day_of_week_number
            if not isinstance(day_of_week_number, int) or day_of_week_number < 1 or day_of_week_number > 7:
                return create_json_response(app, {
                    'message': 'Številka dneva v tednu mora biti med 1 in 7'
                }, 400)
            
            # Validate exercises_status list
            if not isinstance(exercises_status, list) or len(exercises_status) == 0:
                return create_json_response(app, {
                    'message': 'Seznam vaj ne sme biti prazen'
                }, 400)
            
            # Validate each exercise status
            for i, exercise_status in enumerate(exercises_status):
                if not isinstance(exercise_status, dict):
                    return create_json_response(app, {
                        'message': f'Vaja {i+1} mora biti objekt'
                    }, 400)
                
                if 'exercise_id' not in exercise_status or 'finished' not in exercise_status:
                    return create_json_response(app, {
                        'message': f'Vaja {i+1} mora vsebovati exercise_id in finished'
                    }, 400)
                
                if not isinstance(exercise_status['exercise_id'], int) or exercise_status['exercise_id'] <= 0:
                    return create_json_response(app, {
                        'message': f'ID vaje {i+1} mora biti pozitivno celo število'
                    }, 400)
                
                if not isinstance(exercise_status['finished'], bool):
                    return create_json_response(app, {
                        'message': f'Finished status vaje {i+1} mora biti boolean'
                    }, 400)
            
            # Save finished exercises
            result = AthleteManager.save_finished_exercises(
                current_athlete_id, 
                microcycle_id, 
                day_of_week_number, 
                exercises_status
            )
            
            return create_json_response(app, {
                'message': result['message'],
                'updated_exercises': result['updated_exercises'],
                'failed_exercises': result['failed_exercises']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri shranjevanju stanja vaj: {error_message}")
            
            if "ne pripada temu športniku" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri shranjevanju stanja vaj'
                }, 500)



@user_ns.route('/trainer/create-test')
class TrainerCreateTest(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(create_test_model, validate=True)
    @auth_ns.response(201, 'Test uspešno ustvarjen', create_test_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden ali ni dodeljen trenerju')
    @role_required(TRAINER)
    def post(self):
        """Ustvari nov test za športnika"""
        try:
            current_trainer_id = int(get_jwt_identity())
            data = request.get_json()
            
            # Extract data
            athlete_id = data.get('athlete_id')
            test_date = data.get('date')
            exercises = data.get('exercises')
            
            # Validate required fields
            if not athlete_id or not test_date or not exercises:
                return create_json_response(app, {
                    'message': 'Vsi podatki (athlete_id, date, exercises) so obvezni'
                }, 400)
            
            # Validate athlete_id
            if not isinstance(athlete_id, int) or athlete_id <= 0:
                return create_json_response(app, {
                    'message': 'ID športnika mora biti pozitivno celo število'
                }, 400)
            
            # Validate date format
            if not test_date or len(test_date) != 10:
                return create_json_response(app, {
                    'message': 'Datum mora biti v formatu YYYY-MM-DD'
                }, 400)
            
            # Validate exercises list
            if not isinstance(exercises, list) or len(exercises) == 0:
                return create_json_response(app, {
                    'message': 'Seznam vaj ne sme biti prazen'
                }, 400)
            
            # Validate each exercise
            for i, exercise in enumerate(exercises):
                if not isinstance(exercise, dict):
                    return create_json_response(app, {
                        'message': f'Vaja {i+1} mora biti objekt'
                    }, 400)
                
                required_fields = ['exercise_id', 'measure', 'unit']
                missing_fields = [field for field in required_fields if field not in exercise]
                
                if missing_fields:
                    return create_json_response(app, {
                        'message': f'Vaja {i+1} manjka polja: {", ".join(missing_fields)}'
                    }, 400)
                
                if not isinstance(exercise['exercise_id'], int) or exercise['exercise_id'] <= 0:
                    return create_json_response(app, {
                        'message': f'ID vaje {i+1} mora biti pozitivno celo število'
                    }, 400)
                
                if not isinstance(exercise['measure'], (int, float)):
                    return create_json_response(app, {
                        'message': f'Meritev vaje {i+1} mora biti število'
                    }, 400)
                
                if not isinstance(exercise['unit'], str) or not exercise['unit'].strip():
                    return create_json_response(app, {
                        'message': f'Enota vaje {i+1} mora biti neprazen niz'
                    }, 400)
            
            # Create test
            message = TrainerManager.create_test(current_trainer_id, athlete_id, test_date, exercises)
            
            return create_json_response(app, {
                'message': message
            }, 201)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri ustvarjanju testa: {error_message}")
            
            if "ni dodeljen temu trenerju" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 404)
            elif "ne obstaja" in error_message:
                return create_json_response(app, {
                    'message': error_message
                }, 400)
            else:
                return create_json_response(app, {
                    'message': 'Napaka pri ustvarjanju testa'
                }, 500)

@user_ns.route('/athlete/get-test-analytics')
class AthleteGetTestAnalytics(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Test analitika uspešno pridobljena', athlete_test_analytics_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo športniki imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden')
    @role_required(ATHLETE)
    def get(self):
        """Pridobi analitiko vseh testov trenutnega športnika"""
        try:
            current_athlete_id = int(get_jwt_identity())
            
            # Verify athlete exists
            athlete = UserManager.get_user_by_id(current_athlete_id)
            if not athlete:
                return create_json_response(app, {'message': 'Športnik ni najden'}, 404)
            
            # Get test analytics for athlete
            analytics = AthleteManager.get_test_analytics(current_athlete_id)
            
            return create_json_response(app, {
                'message': 'Test analitika uspešno pridobljena',
                'athlete_id': analytics['athlete_id'],
                'total_tests': analytics['total_tests'],
                'tests': analytics['tests']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju test analitike: {error_message}")
            
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju test analitike'
            }, 500)

@user_ns.route('/athlete/get-motor-ability-analytics')
class AthleteGetMotorAbilityAnalytics(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Analitika motoričnih sposobnosti uspešno pridobljena', athlete_motor_ability_analytics_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo športniki imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden')
    @role_required(ATHLETE)
    def get(self):
        """Pridobi analitiko motoričnih sposobnosti za vse teste trenutnega športnika"""
        try:
            current_athlete_id = int(get_jwt_identity())
            
            # Verify athlete exists
            athlete = UserManager.get_user_by_id(current_athlete_id)
            if not athlete:
                return create_json_response(app, {'message': 'Športnik ni najden'}, 404)
            
            # Get motor ability analytics for athlete
            analytics = AthleteManager.get_motor_ability_analytics(current_athlete_id)
            
            return create_json_response(app, {
                'message': 'Analitika motoričnih sposobnosti uspešno pridobljena',
                'athlete_id': analytics['athlete_id'],
                'total_tests': analytics['total_tests'],
                'tests': analytics['tests']
            }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju analitike motoričnih sposobnosti: {error_message}")
            
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju analitike motoričnih sposobnosti'
            }, 500)


@user_ns.route('/athlete/get-tests')
class AthleteGetTests(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Testi uspešno pridobljeni', athlete_tests_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo športniki imajo dostop')
    @auth_ns.response(404, 'Športnik ni najden')
    @role_required(ATHLETE)
    def get(self):
        """Pridobi vse teste trenutnega športnika"""
        try:
            current_athlete_id = int(get_jwt_identity())
            
            # Verify athlete exists
            athlete = UserManager.get_user_by_id(current_athlete_id)
            if not athlete:
                return create_json_response(app, {'message': 'Športnik ni najden'}, 404)
            
            # Get athlete's tests
            tests = AthleteManager.get_tests(current_athlete_id)
            
            return create_json_response(app, {
                'message': 'Testi uspešno pridobljeni',
                'tests': tests,
                'count': len(tests)
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testov: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju testov'
            }, 500)

@user_ns.route('/athlete/microcycle-info')
class AthleteGetMicrocycleInfo(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.expect(athlete_microcycle_request_model)
    @auth_ns.response(200, 'Informacije o mikrociklu uspešno pridobljene', athlete_microcycle_response_model)
    @auth_ns.response(400, 'Neveljavni podatki', error_response_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo športniki imajo dostop')
    @auth_ns.response(404, 'Datum ni znotraj nobene periodizacije')
    @role_required(ATHLETE)
    def post(self):
        """Pridobi informacije o mikrociklu za trenutni dan športnika"""
        try:
            current_athlete_id = int(get_jwt_identity())
            data = request.get_json() or {}
            
            # Get current date from request or use today
            current_date = data.get('current_date')
            
            # Validate date format if provided
            if current_date:
                try:
                    from datetime import datetime
                    datetime.strptime(current_date, '%Y-%m-%d')
                except ValueError:
                    return create_json_response(app, {
                        'message': 'Neveljaven datum. Uporabite format YYYY-MM-DD'
                    }, 400)
            
            # Get microcycle info for athlete
            microcycle_info = AthleteManager.get_athlete_microcycle_info(current_athlete_id, current_date)
            
            # Handle different scenarios
            if not microcycle_info['within_periodization']:
                # Date is not within any periodization - return 404
                return create_json_response(app, {
                    'message': 'Datum ni znotraj nobene periodizacije',
                    'athlete_id': microcycle_info['athlete_id'],
                    'current_date': microcycle_info['current_date'],
                    'day_of_week_number': microcycle_info['day_of_week_number']
                }, 404)
            
            elif microcycle_info['microcycle_id'] is None:
                # Within periodization but no exercises for this day - return 200 with empty methods
                return create_json_response(app, {
                    'message': 'Znotraj periodizacije, a ni vaj za ta dan',
                    'athlete_id': microcycle_info['athlete_id'],
                    'current_date': microcycle_info['current_date'],
                    'day_of_week_number': microcycle_info['day_of_week_number'],
                    'within_periodization': True,
                    'periodization_id': microcycle_info.get('periodization_id'),
                    'periodization_name': microcycle_info.get('periodization_name'),
                    'microcycle_id': None,
                    'methods': []
                }, 200)
            
            else:
                # Normal case - exercises found
                return create_json_response(app, {
                    'message': 'Informacije o mikrociklu uspešno pridobljene',
                    'athlete_id': microcycle_info['athlete_id'],
                    'current_date': microcycle_info['current_date'],
                    'day_of_week_number': microcycle_info['day_of_week_number'],
                    'within_periodization': True,
                    'periodization_id': microcycle_info.get('periodization_id'),
                    'periodization_name': microcycle_info.get('periodization_name'),
                    'microcycle_id': microcycle_info['microcycle_id'],
                    'active_rest': microcycle_info['active_rest'],
                    'methods': microcycle_info['methods']
                }, 200)
            
        except Exception as e:
            error_message = str(e)
            log_with_unicode(f"✗ Napaka pri pridobivanju informacij o mikrociklu: {error_message}")
            
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju informacij o mikrociklu'
            }, 500)


@user_ns.route('/trainer/get-tests')
class TrainerGetTests(Resource):
    @auth_ns.doc(security='Bearer')
    @auth_ns.response(200, 'Testi uspešno pridobljeni', tests_list_model)
    @auth_ns.response(401, 'Žeton je obvezen')
    @auth_ns.response(403, 'Samo trenerji imajo dostop')
    @auth_ns.response(404, 'Trener ni najden')
    @role_required(TRAINER)
    def get(self):
        """Pridobi vse teste trenutnega trenerja"""
        try:
            current_trainer_id = int(get_jwt_identity())
            
            # Verify trainer exists
            trainer = UserManager.get_user_by_id(current_trainer_id)
            if not trainer:
                return create_json_response(app, {'message': 'Trener ni najden'}, 404)
            
            # Get trainer's tests
            tests = TrainerManager.get_tests(current_trainer_id)
            
            return create_json_response(app, {
                'message': 'Testi uspešno pridobljeni',
                'tests': tests,
                'count': len(tests)
            }, 200)
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testov: {e}")
            return create_json_response(app, {
                'message': 'Napaka pri pridobivanju testov'
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
    app.run(host='0.0.0.0', port=5000,debug=True)
