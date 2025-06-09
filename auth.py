from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from database import db_manager
from utils import format_user_data, sanitize_input, log_with_unicode
import oracledb
from datetime import timedelta
import math

bcrypt = Bcrypt()

class UserManager:
    @staticmethod
    def register_user(first_name, last_name, phone_number, email, password, role):
        """Register a new user with bcrypt password hashing"""
        try:
            # Sanitize inputs while preserving Slovenian characters
            first_name = sanitize_input(first_name)
            last_name = sanitize_input(last_name)
            phone_number = sanitize_input(phone_number)
            email = sanitize_input(email.lower())
            
            # Hash password with bcrypt in Python
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Check if email already exists
            existing_user = UserManager.get_user_by_email(email)
            if existing_user:
                raise Exception("Uporabnik s tem e-poštnim naslovom že obstaja")
            
            # Insert user directly with SQL (not stored procedure)
            query = """
                INSERT INTO users (first_name, last_name, phone_number, email, password, role)
                VALUES (:1, :2, :3, :4, :5, :6)
                RETURNING id INTO :7
            """
            
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Create output variable for returned user ID
            user_id_var = cursor.var(oracledb.NUMBER)
            
            cursor.execute(query, [
                first_name, last_name, phone_number, 
                email, hashed_password, role, user_id_var
            ])
            
            user_id = user_id_var.getvalue()
            connection.commit()
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Uporabnik uspešno registriran - ID: {user_id}")
            return user_id
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri registraciji: {e}")
            raise

    @staticmethod
    def login_user(email, password):
        """Authenticate user using bcrypt password verification"""
        try:
            email = sanitize_input(email.lower())
            
            # Get user data including password hash
            user_data = UserManager.get_user_by_email(email)
            
            if not user_data:
                log_with_unicode(f"✗ Uporabnik ni najden: {email}")
                return None
            
            # Verify password using bcrypt
            if bcrypt.check_password_hash(user_data['PASSWORD'], password):
                log_with_unicode(f"✓ Uspešna prijava: {email}")
                
                # Format user data (exclude password from response)
                formatted_user = format_user_data({
                    'id': user_data['ID'],
                    'first_name': user_data['FIRST_NAME'],
                    'last_name': user_data['LAST_NAME'],
                    'phone_number': user_data['PHONE_NUMBER'],
                    'email': user_data['EMAIL'],
                    'role': user_data['ROLE']
                })
                
                return formatted_user
            else:
                log_with_unicode(f"✗ Napačno geslo: {email}")
                return None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri prijavi: {e}")
            raise

    @staticmethod
    def get_user_by_email(email):
        """Get user by email including password hash for authentication"""
        try:
            query = """
                SELECT id, first_name, last_name, phone_number, email, password, role 
                FROM users 
                WHERE LOWER(email) = LOWER(:1)
            """
            
            result = db_manager.execute_query(query, [email])
            
            if result:
                return result[0]  # Return first (and should be only) result
            return None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju uporabnika po e-pošti {email}: {e}")
            raise

    @staticmethod
    def get_user_by_id(user_id):
        """Get user details by ID (exclude password)"""
        try:
            query = """
                SELECT id, first_name, last_name, phone_number, email, role 
                FROM users 
                WHERE id = :1
            """
            
            result = db_manager.execute_query(query, [user_id])
            
            if result:
                user_data = result[0]
                formatted_user = format_user_data({
                    'id': user_data['ID'],
                    'first_name': user_data['FIRST_NAME'],
                    'last_name': user_data['LAST_NAME'],
                    'phone_number': user_data['PHONE_NUMBER'],
                    'email': user_data['EMAIL'],
                    'role': user_data['ROLE']
                })
                return formatted_user
            return None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju uporabnika {user_id}: {e}")
            raise

    @staticmethod
    def update_user(user_id, update_data):
        """Update user data (excluding password)"""
        try:
            # Sanitize inputs
            sanitized_data = {}
            for key, value in update_data.items():
                if isinstance(value, str) and key != 'password':
                    sanitized_data[key] = sanitize_input(value)
                else:
                    sanitized_data[key] = value
            
            # Build dynamic update query
            set_clauses = []
            params = []
            
            for key, value in sanitized_data.items():
                if key in ['first_name', 'last_name', 'phone_number', 'email']:
                    set_clauses.append(f"{key} = :{len(params) + 1}")
                    params.append(value)
            
            if not set_clauses:
                raise Exception("Ni podatkov za posodobitev")
            
            # Check if email already exists for another user
            if 'email' in sanitized_data:
                existing_user = UserManager.get_user_by_email(sanitized_data['email'])
                if existing_user and existing_user['ID'] != user_id:
                    raise Exception("E-poštni naslov že obstaja za drugega uporabnika")
            
            # Add user_id as last parameter
            params.append(user_id)
            
            query = f"""
                UPDATE users 
                SET {', '.join(set_clauses)}
                WHERE id = :{len(params)}
            """
            
            rows_affected = db_manager.execute_dml(query, params)
            
            if rows_affected > 0:
                log_with_unicode(f"✓ Uporabnik {user_id} uspešno posodobljen")
                return True
            else:
                log_with_unicode(f"✗ Uporabnik {user_id} ni najden")
                return False
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri posodabljanju uporabnika {user_id}: {e}")
            raise

    @staticmethod
    def update_user_password(user_id, new_password):
        """Update user password with bcrypt hashing"""
        try:
            # Validate password length
            if len(new_password) < 6:
                raise Exception("Geslo mora imeti vsaj 6 znakov")
            
            # Hash new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            query = """
                UPDATE users 
                SET password = :1
                WHERE id = :2
            """
            
            rows_affected = db_manager.execute_dml(query, [hashed_password, user_id])
            
            if rows_affected > 0:
                log_with_unicode(f"✓ Geslo uporabnika {user_id} uspešno posodobljeno")
                return True
            else:
                log_with_unicode(f"✗ Uporabnik {user_id} ni najden")
                return False
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri posodabljanju gesla {user_id}: {e}")
            raise

    @staticmethod
    def check_email_exists(email):
        """Check if email exists"""
        try:
            user = UserManager.get_user_by_email(email)
            return user is not None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri preverjanju e-pošte: {e}")
            return False

    @staticmethod
    def check_user_exists(user_id):
        """Check if user exists"""
        try:
            user = UserManager.get_user_by_id(user_id)
            return user is not None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri preverjanju uporabnika: {e}")
            return False




class PeriodizationManager:
    @staticmethod
    def get_periodization_info(periodization_id):
        """Get detailed periodization information including mesocycles and microcycles data"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Get basic periodization info
            periodization_query = """
                SELECT 
                    id,
                    periodization_name,
                    difficulty,
                    CAST(date_from AS DATE) as start_date,
                    CAST(date_to AS DATE) as end_date
                FROM periodizations
                WHERE id = :1
            """
            
            cursor.execute(periodization_query, [periodization_id])
            periodization_data = cursor.fetchone()
            
            if not periodization_data:
                raise Exception(f"Periodizacija z ID {periodization_id} ne obstaja")
            
            # Calculate duration in weeks
            start_date = periodization_data[3]
            end_date = periodization_data[4]
            duration_weeks = round((end_date - start_date).days / 7, 1)
            
            # Get mesocycles data
            mesocycles_query = """
                SELECT id, number_of_microcycles
                FROM mesocycles
                WHERE periodization_id = :1
                ORDER BY id ASC
            """
            
            cursor.execute(mesocycles_query, [periodization_id])
            mesocycles_data = cursor.fetchall()
            
            mesocycles = []
            for meso in mesocycles_data:
                mesocycle_id = meso[0]
                number_of_microcycles = meso[1]
                
                # Get microcycles for this mesocycle with active_rest info
                microcycles_query = """
                    SELECT id, first_micro_start_date, 
                           CASE WHEN active_rest IS NULL THEN 0 ELSE active_rest END as active_rest
                    FROM microcycles
                    WHERE mesocycle_id = :1
                    ORDER BY id ASC
                """
                
                cursor.execute(microcycles_query, [mesocycle_id])
                microcycles_data = cursor.fetchall()
                
                microcycles = []
                for micro in microcycles_data:
                    microcycle_obj = {
                        'id': micro[0],
                        'start_date': micro[1].strftime('%Y-%m-%d') if micro[1] else None,
                        'active_rest': bool(micro[2])  # Convert to boolean
                    }
                    microcycles.append(microcycle_obj)
                
                # Get motor abilities for this mesocycle
                motor_abilities_query = """
                    SELECT DISTINCT ma.motor_ability
                    FROM motor_abilities ma
                    JOIN methods m ON ma.id = m.motor_ability_id
                    JOIN exercises e ON m.id = e.method_id
                    JOIN exercises_microcycles em ON e.id = em.exercise_id
                    JOIN microcycles mc ON em.microcycle_id = mc.id
                    WHERE mc.mesocycle_id = :1
                    ORDER BY ma.motor_ability
                """
                
                cursor.execute(motor_abilities_query, [mesocycle_id])
                motor_abilities = [row[0] for row in cursor.fetchall()]
                
                # Get training methods for this mesocycle
                methods_query = """
                    SELECT DISTINCT m.method_name
                    FROM methods m
                    JOIN exercises e ON m.id = e.method_id
                    JOIN exercises_microcycles em ON e.id = em.exercise_id
                    JOIN microcycles mc ON em.microcycle_id = mc.id
                    WHERE mc.mesocycle_id = :1
                    ORDER BY m.method_name
                """
                
                cursor.execute(methods_query, [mesocycle_id])
                training_methods = [row[0] for row in cursor.fetchall()]
                
                # Get method groups for this mesocycle
                method_groups_query = """
                    SELECT DISTINCT m.method_group
                    FROM methods m
                    JOIN exercises e ON m.id = e.method_id
                    JOIN exercises_microcycles em ON e.id = em.exercise_id
                    JOIN microcycles mc ON em.microcycle_id = mc.id
                    WHERE mc.mesocycle_id = :1
                    ORDER BY m.method_group
                """
                
                cursor.execute(method_groups_query, [mesocycle_id])
                method_groups = [row[0] for row in cursor.fetchall()]
                
                # Get most common exercises per method for this mesocycle
                key_exercises_query = """
                    WITH exercise_counts AS (
                        SELECT 
                            e.method_id,
                            e.id AS exercise_id,
                            e.exercise AS exercise_name,
                            m.method_name,
                            COUNT(*) AS usage_count,
                            ROW_NUMBER() OVER (PARTITION BY e.method_id ORDER BY COUNT(*) DESC, e.id) AS rn
                        FROM exercises_microcycles em
                        JOIN exercises e ON em.exercise_id = e.id
                        JOIN microcycles mc ON em.microcycle_id = mc.id
                        JOIN methods m ON e.method_id = m.id
                        WHERE mc.mesocycle_id = :1
                        GROUP BY e.method_id, e.id, e.exercise, m.method_name
                    )
                    SELECT method_id, exercise_id, exercise_name, method_name, usage_count
                    FROM exercise_counts
                    WHERE rn = 1
                    ORDER BY method_id
                """
                
                cursor.execute(key_exercises_query, [mesocycle_id])
                key_exercises_data = cursor.fetchall()
                
                key_exercises = []
                for exercise in key_exercises_data:
                    key_exercises.append({
                        'method_id': exercise[0],
                        'exercise_id': exercise[1],
                        'exercise_name': exercise[2],
                        'method_name': exercise[3],
                        'usage_count': exercise[4]
                    })
                
                # Build mesocycle object with microcycles included
                mesocycle_obj = {
                    'id': mesocycle_id,
                    'number_of_microcycles': number_of_microcycles,
                    'microcycles': microcycles,  # Added microcycles array
                    'motor_abilities': motor_abilities,
                    'training_methods': training_methods,
                    'method_groups': method_groups,
                    'key_exercises': key_exercises
                }
                
                mesocycles.append(mesocycle_obj)
            
            cursor.close()
            connection.close()
            
            # Build final response
            result = {
                'id': periodization_data[0],
                'name': periodization_data[1],
                'difficulty': periodization_data[2],
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d'),
                'duration_weeks': duration_weeks,
                'mesocycles': mesocycles
            }
            
            log_with_unicode(f"✓ Pridobljene informacije za periodizacijo {periodization_id}")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju informacij o periodizaciji {periodization_id}: {e}")
            raise






# Keep TrainerManager as is - it doesn't need password handling
class TrainerManager:
    @staticmethod
    def get_trainer_periodizations(trainer_id):
        """Get all periodizations for a trainer using Oracle cursor function"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Call the cursor function (not the pipelined function)
            periodizations_cursor = cursor.callfunc(
                'PKG_INFORMATION_VIEW.get_periodizations_cursor',
                oracledb.CURSOR, 
                [trainer_id]
            )
            
            # Get column names from the cursor description
            columns = [col[0] for col in periodizations_cursor.description]
            rows = periodizations_cursor.fetchall()
            
            # Format results with Unicode handling
            from utils import format_database_results
            result = format_database_results(rows, columns)
            
            periodizations_cursor.close()
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Pridobljenih {len(result)} periodizacij za trenerja {trainer_id}")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju periodizacij za trenerja {trainer_id}: {e}")
            log_with_unicode(f"✗ Detailed error: {str(e)}")
            raise Exception(f"Napaka pri pridobivanju periodizacij: {str(e)}")
    
    
    @staticmethod
    def search_athletes():
        """Get all available athletes (not assigned to any trainer)"""
        try:
            # Get athletes that are not yet assigned to any trainer
            query = """
                SELECT u.id, u.first_name, u.last_name, u.email, u.role
                FROM users u
                WHERE u.role = 1
                AND NOT EXISTS (
                    SELECT 1 FROM trainers_athletes ta 
                    WHERE ta.athlete_id = u.id
                )
                ORDER BY u.last_name, u.first_name
            """
            
            result = db_manager.execute_query(query)
            
            # Format results with Unicode handling
            from utils import format_user_data
            formatted_athletes = []
            for athlete in result:
                formatted_athlete = format_user_data({
                    'id': athlete['ID'],
                    'first_name': athlete['FIRST_NAME'],
                    'last_name': athlete['LAST_NAME'],
                    'email': athlete['EMAIL'],
                    'role': athlete['ROLE']
                })
                formatted_athletes.append(formatted_athlete)
            
            log_with_unicode(f"✓ Najdenih {len(formatted_athletes)} razpoložljivih športnikov")
            return formatted_athletes
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri iskanju športnikov: {e}")
            raise Exception(f"Napaka pri iskanju športnikov: {str(e)}")
    
    
    @staticmethod
    def get_test_exercises():
        """Get all test exercises grouped by motor ability and method group"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Get motor abilities that have test exercises
            motor_abilities_query = """
                SELECT DISTINCT ma.id, ma.motor_ability 
                FROM motor_abilities ma
                JOIN methods m ON ma.id = m.motor_ability_id
                JOIN exercises e ON m.id = e.method_id
                WHERE e.test = 1
                ORDER BY ma.motor_ability
            """
            cursor.execute(motor_abilities_query)
            motor_abilities = cursor.fetchall()
            
            result = []
            for ma in motor_abilities:
                motor_ability_id = ma[0]
                motor_ability_name = ma[1]
                
                # Get method groups for this motor ability that have test exercises
                method_groups_query = """
                    SELECT DISTINCT m.method_group
                    FROM methods m
                    JOIN exercises e ON m.id = e.method_id
                    WHERE m.motor_ability_id = :1
                      AND e.test = 1
                    ORDER BY m.method_group
                """
                cursor.execute(method_groups_query, [motor_ability_id])
                method_groups = cursor.fetchall()
                
                method_groups_list = []
                for mg in method_groups:
                    method_group_name = mg[0]
                    
                    # Get test exercises for this motor ability and method group
                    exercises_query = """
                        SELECT e.id, e.exercise, e.description, e.video_url
                        FROM exercises e
                        JOIN methods m ON e.method_id = m.id
                        WHERE m.motor_ability_id = :1
                          AND m.method_group = :2
                          AND e.test = 1
                        ORDER BY e.exercise
                    """
                    cursor.execute(exercises_query, [motor_ability_id, method_group_name])
                    exercises = cursor.fetchall()
                    
                    exercises_list = []
                    for exercise in exercises:
                        exercises_list.append({
                            'id': exercise[0],
                            'exercise': exercise[1],
                            'description': exercise[2],
                            'video_url': exercise[3]
                        })
                    
                    method_groups_list.append({
                        'method_group': method_group_name,
                        'exercises': exercises_list
                    })
                
                result.append({
                    'motor_ability': motor_ability_name,
                    'method_groups': method_groups_list
                })
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Pridobljene testne vaje razvrščene po motoričnih sposobnostih")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testnih vaj: {e}")
            raise Exception(f"Napaka pri pridobivanju testnih vaj: {str(e)}")


    @staticmethod
    def get_past_test_exercises(trainer_id, test_date, athlete_id):
        """Get exercise IDs and units from most recent test within last 2 months"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First verify that athlete belongs to this trainer
            athlete_check_query = """
                SELECT COUNT(*) as count
                FROM trainers_athletes ta
                JOIN users u ON ta.athlete_id = u.id
                WHERE ta.trainer_id = :1 AND ta.athlete_id = :2 AND u.role = 1
            """
            cursor.execute(athlete_check_query, [trainer_id, athlete_id])
            result = cursor.fetchone()
            
            if result[0] == 0:
                raise Exception("Športnik ni dodeljen temu trenerju ali ne obstaja")
            
            # FIXED: Handle DD-MON-RR format properly using Oracle DATE functions
            past_tests_query = """
                SELECT id, test_date
                FROM tests
                WHERE trainer_id = :1 
                  AND athlete_id = :2
                  AND TO_DATE(test_date, 'DD-MON-RR') >= TO_DATE(:3, 'YYYY-MM-DD') - INTERVAL '2' MONTH
                  AND TO_DATE(test_date, 'DD-MON-RR') < TO_DATE(:4, 'YYYY-MM-DD')
                ORDER BY TO_DATE(test_date, 'DD-MON-RR') DESC, id DESC
            """
            
            log_with_unicode(f"🔍 Searching for tests between {test_date} - 2 months and {test_date}")
            log_with_unicode(f"🔍 Converting DD-MON-RR format to DATE for comparison")
            
            cursor.execute(past_tests_query, [trainer_id, athlete_id, test_date, test_date])
            past_tests = cursor.fetchall()
            
            log_with_unicode(f"🔍 Found {len(past_tests)} past tests using proper date conversion")
            
            if not past_tests:
                return {
                    'most_recent_test_id': None,
                    'most_recent_test_date': None,
                    'exercises': [],
                    'found_past_test': False
                }
            
            # Get the most recent test (first in the ordered result)
            most_recent_test = past_tests[0]
            most_recent_test_id = most_recent_test[0]
            most_recent_test_date = most_recent_test[1]
            
            log_with_unicode(f"✓ Most recent test found: ID {most_recent_test_id}, Date: {most_recent_test_date}")
            
            # Get exercise IDs and units from the most recent test
            exercises_query = """
                SELECT DISTINCT exercise_id, unit
                FROM exercises_tests
                WHERE test_id = :1
                ORDER BY exercise_id
            """
            
            cursor.execute(exercises_query, [most_recent_test_id])
            exercise_data = cursor.fetchall()
            
            exercises = []
            for row in exercise_data:
                exercises.append({
                    'exercise_id': row[0],
                    'unit': row[1]
                })
            
            cursor.close()
            connection.close()
            
            result = {
                'most_recent_test_id': most_recent_test_id,
                'most_recent_test_date': most_recent_test_date,
                'exercises': exercises,
                'found_past_test': True
            }
            
            log_with_unicode(f"✓ Successfully found test {most_recent_test_id} with {len(exercises)} exercises")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri iskanju prejšnjih testov: {e}")
            raise

    @staticmethod
    def get_tests(trainer_id):
        """Get all tests for a specific trainer"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Get tests with athlete information
            tests_query = """
                SELECT 
                    t.id,
                    t.test_date,
                    u.first_name,
                    u.last_name
                FROM tests t
                JOIN users u ON t.athlete_id = u.id
                WHERE t.trainer_id = :1
                ORDER BY t.test_date DESC, t.id DESC
            """
            
            cursor.execute(tests_query, [trainer_id])
            tests_data = cursor.fetchall()
            
            tests = []
            for test_data in tests_data:
                # Since test_date is varchar in database, handle it as string
                test_date_raw = test_data[1]
                first_name = test_data[2]
                last_name = test_data[3]
                
                # Create full name
                full_name = f"{first_name} {last_name}" if first_name and last_name else None
                
                test_obj = {
                    'id': test_data[0],
                    'test_date': test_date_raw,  # Keep as string since it's varchar in DB
                    'athlete_full_name': full_name
                }
                tests.append(test_obj)
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Pridobljenih {len(tests)} testov za trenerja {trainer_id}")
            return tests
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju testov za trenerja {trainer_id}: {e}")
            raise Exception(f"Napaka pri pridobivanju testov: {str(e)}")
    
    @staticmethod
    def create_test(trainer_id, athlete_id, test_date, exercises):
        """Create a test with provided inputs - individual inserts for each exercise"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First, verify the athlete exists and belongs to this trainer
            athlete_check_query = """
                SELECT COUNT(*) as count
                FROM trainers_athletes ta
                JOIN users u ON ta.athlete_id = u.id
                WHERE ta.trainer_id = :1 AND ta.athlete_id = :2 AND u.role = 1
            """
            cursor.execute(athlete_check_query, [trainer_id, athlete_id])
            result = cursor.fetchone()
            
            if result[0] == 0:
                raise Exception("Športnik ni dodeljen temu trenerju ali ne obstaja")
            
            # Insert test record and get test_id (FIXED: Handle list return)
            insert_test_query = """
                INSERT INTO tests (athlete_id, trainer_id, test_date)
                VALUES (:1, :2, TO_DATE(:3, 'YYYY-MM-DD'))
                RETURNING id INTO :4
            """
            test_id_var = cursor.var(oracledb.NUMBER)
            cursor.execute(insert_test_query, [athlete_id, trainer_id, test_date, test_id_var])
            
            # FIX: Handle the returned value properly
            test_id_raw = test_id_var.getvalue()
            log_with_unicode(f"🔍 Raw test_id from database: {test_id_raw} (type: {type(test_id_raw)})")
            
            # Handle case where test_id comes back as a list
            if isinstance(test_id_raw, list):
                if len(test_id_raw) > 0:
                    test_id = test_id_raw[0]
                    log_with_unicode(f"⚠️ test_id was a list, taking first element: {test_id}")
                else:
                    raise Exception("Napaka: test_id je prazen seznam")
            else:
                test_id = test_id_raw
            
            log_with_unicode(f"✓ Test ustvarjen z ID: {test_id}")
            
            # Process each exercise individually
            successful_inserts = 0
            
            for i, exercise in enumerate(exercises):
                try:
                    # DEBUG: Print the exercise data to see what we're getting
                    log_with_unicode(f"🔍 Processing exercise {i+1}: {exercise}")
                    
                    # Extract values - these should be simple values based on your debug output
                    exercise_id = exercise.get('exercise_id')
                    measure = exercise.get('measure')
                    unit = exercise.get('unit')
                    
                    # Validate each exercise data
                    if exercise_id is None or measure is None or unit is None:
                        raise Exception(f'Vsi podatki za vajo {i+1} (exercise_id, measure, unit) so obvezni')
                    
                    # Convert to proper types with error handling
                    try:
                        exercise_id_int = int(exercise_id)
                        measure_float = float(measure)
                        unit_str = str(unit).strip()
                    except (ValueError, TypeError) as conv_error:
                        raise Exception(f'Napaka pri pretvorbi podatkov za vajo {i+1}: {conv_error}')
                    
                    # Verify exercise exists
                    exercise_check_query = "SELECT COUNT(*) FROM exercises WHERE id = :1"
                    cursor.execute(exercise_check_query, [exercise_id_int])
                    exercise_exists = cursor.fetchone()
                    if exercise_exists[0] == 0:
                        raise Exception(f'Vaja z ID {exercise_id_int} ne obstaja')
                    
                    # Insert individual exercise test record (FIX: Ensure test_id is properly converted)
                    insert_exercise_test_query = """
                        INSERT INTO exercises_tests (test_id, exercise_id, measure, unit)
                        VALUES (:1, :2, :3, :4)
                    """
                    
                    # FIX: Convert test_id to int here, after handling list case above
                    test_id_final = int(test_id)
                    log_with_unicode(f"🔍 Final values for DB insert: test_id={test_id_final}, exercise_id={exercise_id_int}, measure={measure_float}, unit={unit_str}")
                    
                    cursor.execute(insert_exercise_test_query, [
                        test_id_final,     # Now this should be a proper integer
                        exercise_id_int,
                        measure_float,
                        unit_str
                    ])
                    
                    successful_inserts += 1
                    log_with_unicode(f"✓ Vaja {i+1} (ID: {exercise_id_int}) uspešno dodana v test")
                    
                except Exception as exercise_error:
                    log_with_unicode(f"✗ Napaka pri dodajanju vaje {i+1}: {exercise_error}")
                    # Re-raise the exception to stop the entire process
                    raise Exception(f"Napaka pri vaji {i+1}: {str(exercise_error)}")
            
            # If we get here, all exercises were inserted successfully
            connection.commit()
            cursor.close()
            connection.close()
            
            success_message = f"Test z ID {test_id} je bil uspešno ustvarjen z {successful_inserts} vajami"
            log_with_unicode(f"✓ {success_message}")
            return success_message
            
        except Exception as e:
            # Make sure to rollback on any error
            try:
                if 'connection' in locals():
                    connection.rollback()
                    cursor.close()
                    connection.close()
            except:
                pass
            log_with_unicode(f"✗ Napaka pri ustvarjanju testa: {e}")
            raise

    @staticmethod
    def delete_test(trainer_id, test_id):
        """Delete a test by ID if it belongs to the trainer"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First verify that the test belongs to the trainer
            check_query = """
                SELECT COUNT(*) as count
                FROM tests
                WHERE id = :1 AND trainer_id = :2
            """
            cursor.execute(check_query, [test_id, trainer_id])
            result = cursor.fetchone()
            
            if result[0] == 0:  # Fixed: access first element of tuple
                raise Exception(f"Test z ID {test_id} ne obstaja ali ni dodeljen temu trenerju")
            
            # Delete the test (cascades will handle related exercises_tests records if configured)
            delete_query = "DELETE FROM tests WHERE id = :1"
            cursor.execute(delete_query, [test_id])
            
            rows_affected = cursor.rowcount
            connection.commit()
            cursor.close()
            connection.close()
            
            if rows_affected > 0:
                success_message = f"Test z ID {test_id} je bil uspešno izbrisan"
                log_with_unicode(f"✓ {success_message}")
                return success_message
            else:
                raise Exception(f"Test z ID {test_id} ni bil najden")
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri brisanju testa {test_id}: {e}")
            raise

    @staticmethod
    def get_test_analytics_by_athlete(trainer_id, athlete_id):
        """Get test analytics for all tests of a specific athlete"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First verify the athlete belongs to the trainer
            athlete_check_query = """
                SELECT COUNT(*) as count
                FROM trainers_athletes ta
                JOIN users u ON ta.athlete_id = u.id
                WHERE ta.trainer_id = :1 AND ta.athlete_id = :2 AND u.role = 1
            """
            cursor.execute(athlete_check_query, [trainer_id, athlete_id])
            result = cursor.fetchone()
            
            if result[0] == 0:
                raise Exception("Športnik ni dodeljen temu trenerju ali ne obstaja")
            
            log_with_unicode(f"✓ Športnik {athlete_id} pripada trenerju {trainer_id}")
            
            # Get all tests for this athlete and trainer, sorted by test_date
            # Handle DD-MON-RR date format properly
            all_tests_query = """
                SELECT id, test_date
                FROM tests
                WHERE athlete_id = :1 AND trainer_id = :2
                ORDER BY TO_DATE(test_date, 'DD-MON-RR') ASC, id ASC
            """
            
            cursor.execute(all_tests_query, [athlete_id, trainer_id])
            tests_data = cursor.fetchall()
            
            log_with_unicode(f"✓ Najdenih {len(tests_data)} testov za športnika {athlete_id}")
            
            tests = []
            for test_data in tests_data:
                current_test_id = test_data[0]
                current_test_date = test_data[1]
                
                # Get exercises for this test
                exercises_query = """
                    SELECT 
                        e.exercise,
                        et.measure,
                        et.unit
                    FROM exercises_tests et
                    JOIN exercises e ON et.exercise_id = e.id
                    WHERE et.test_id = :1
                    ORDER BY e.exercise
                """
                
                cursor.execute(exercises_query, [current_test_id])
                exercises_data = cursor.fetchall()
                
                exercises = []
                for exercise_data in exercises_data:
                    exercise_obj = {
                        'exercise': exercise_data[0],
                        'measure': exercise_data[1],
                        'unit': exercise_data[2]
                    }
                    exercises.append(exercise_obj)
                
                test_obj = {
                    'id': current_test_id,
                    'test_date': current_test_date,
                    'exercises': exercises
                }
                tests.append(test_obj)
            
            cursor.close()
            connection.close()
            
            result = {
                'athlete_id': athlete_id,
                'total_tests': len(tests),
                'tests': tests
            }
            
            log_with_unicode(f"✓ Test analitika pripravljena za {len(tests)} testov športnika {athlete_id}")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju test analitike za športnika {athlete_id}: {e}")
            raise

    @staticmethod
    def normalize_motor_ability_values(motor_abilities_data):
        """Normalize test exercises using biomechanical indices for speed prediction"""
        
        # Biomechanical conversion coefficients for speed prediction (m/s)
        # Based on research and established sport science indices
        speed_conversion_indices = {
            # Horizontal jumping tests (predict horizontal velocity)
            'skok v daljino z mesta': {
                'coefficient': 0.42,  # Distance (m) × 0.42 ≈ horizontal takeoff velocity (m/s)
                'formula': 'sqrt(distance * 9.81 / sin(45°))',  # Projectile motion
                'unit_conversion': 'm/s'
            },
            'troskok iz sonožnega odriva': {
                'coefficient': 0.35,  # Triple jump has different biomechanics
                'formula': 'distance * 0.35',
                'unit_conversion': 'm/s'
            },
            
            # Sprint tests (direct time to speed conversion)
            'šprint letečih 20m': {
                'coefficient': 20.0,  # 20m / time = speed
                'formula': '20 / time',
                'unit_conversion': 'm/s'
            },
            'štart iz bloka 20 m': {
                'coefficient': 20.0,  # 20m / time = speed
                'formula': '20 / time', 
                'unit_conversion': 'm/s'
            },
            
            # Vertical jumping (can estimate power but not direct speed)
            'skok iz čepa': {
                'coefficient': 4.9,  # Height (m) × 4.9 ≈ takeoff velocity
                'formula': 'sqrt(2 * 9.81 * height)',
                'unit_conversion': 'm/s'
            },
            'globinski skok': {
                'coefficient': 4.9,
                'formula': 'sqrt(2 * 9.81 * height)',
                'unit_conversion': 'm/s'
            }
        }
        
        def convert_to_speed_index(exercise_name, measure, unit):
            """Convert exercise result to predicted speed using biomechanical indices"""
            exercise_key = None
            for key in speed_conversion_indices.keys():
                if key.lower() in exercise_name.lower():
                    exercise_key = key
                    break
            
            if not exercise_key:
                # Unknown exercise, try to categorize
                if any(word in exercise_name.lower() for word in ['skok', 'jump']):
                    if 'daljina' in exercise_name.lower() or 'horizontal' in exercise_name.lower():
                        exercise_key = 'skok v daljino z mesta'
                    else:
                        exercise_key = 'skok iz čepa'
                elif any(word in exercise_name.lower() for word in ['šprint', 'sprint', 'štart']):
                    exercise_key = 'šprint letečih 20m'
                else:
                    return measure, unit  # No conversion possible
            
            conversion = speed_conversion_indices[exercise_key]
            
            try:
                if 'time' in unit.lower() or 'sec' in unit.lower():
                    # Time-based exercises (sprints)
                    if 'šprint' in exercise_key or 'štart' in exercise_key:
                        speed_ms = conversion['coefficient'] / measure
                        return speed_ms, 'm/s'
                    
                elif any(dist_unit in unit.lower() for dist_unit in ['m', 'cm', 'meter']):
                    # Distance-based exercises (jumps)
                    if unit.lower() == 'cm':
                        measure_m = measure / 100.0  # Convert cm to m
                    else:
                        measure_m = measure
                    
                    if 'daljina' in exercise_key or 'troskok' in exercise_key:
                        # Horizontal jumps - estimate horizontal velocity
                        speed_ms = measure_m * conversion['coefficient']
                        return speed_ms, 'm/s'
                    else:
                        # Vertical jumps - estimate takeoff velocity
                        import math
                        speed_ms = math.sqrt(2 * 9.81 * measure_m)
                        return speed_ms, 'm/s'
                        
                else:
                    # Unknown unit, return as is
                    return measure, unit
                    
            except (ZeroDivisionError, ValueError, TypeError):
                return measure, unit
        
        def normalize_by_motor_ability(motor_ability, measure, unit, exercise_name):
            """Apply normalization specific to each motor ability with speed indices"""
            
            if motor_ability.lower() == 'hitrost':
                # For Hitrost: convert to predicted speed (m/s) using biomechanical indices
                speed_value, speed_unit = convert_to_speed_index(exercise_name, measure, unit)
                
                # Additional biomechanical scaling based on exercise type
                if 'frekvenca' in exercise_name.lower():
                    # Step frequency component - higher frequency = better
                    normalized_value = speed_value
                    normalized_unit = speed_unit
                elif 'odriv' in exercise_name.lower():
                    # Step power component - more power = better
                    normalized_value = speed_value
                    normalized_unit = speed_unit
                else:
                    # General speed exercise
                    normalized_value = speed_value
                    normalized_unit = speed_unit
                    
            elif motor_ability.lower() == 'moč':
                # Power exercises: normalize by body mass^0.67 or use raw values for jumps
                reference_body_mass = 75.0
                
                if any(jump_word in exercise_name.lower() for jump_word in ['skok', 'jump']):
                    # Jumping exercises: convert to power index or keep raw
                    if any(dist_unit in unit.lower() for dist_unit in ['m', 'cm']):
                        # Distance-based jumps: estimate power
                        if unit.lower() == 'cm':
                            distance_m = measure / 100.0
                        else:
                            distance_m = measure
                        # Power index: distance × body_weight × g / time²
                        # Simplified: use distance as power indicator
                        normalized_value = distance_m * reference_body_mass
                        normalized_unit = "power_index"
                    else:
                        normalized_value = measure
                        normalized_unit = unit
                else:
                    # Strength exercises: allometric scaling
                    normalized_value = measure / (reference_body_mass ** 0.67)
                    normalized_unit = f"{unit}/kg^0.67"
                    
            elif motor_ability.lower() == 'vzdržljivost':
                # Endurance: convert time to performance score
                if any(time_unit in unit.lower() for time_unit in ['sec', 'min', 'time']):
                    normalized_value = 1000 / measure if measure > 0 else 0
                    normalized_unit = "endurance_score"
                else:
                    normalized_value = measure
                    normalized_unit = unit
                    
            elif motor_ability.lower() == 'gibljivost':
                # Flexibility: use raw values
                normalized_value = measure
                normalized_unit = unit
                
            elif motor_ability.lower() == 'koordinacija':
                # Coordination: depends on measure type
                if any(time_unit in unit.lower() for time_unit in ['sec', 'time']):
                    normalized_value = 100 / measure if measure > 0 else 0
                    normalized_unit = "coordination_score"
                elif 'error' in unit.lower():
                    normalized_value = 100 - measure if measure < 100 else 0
                    normalized_unit = "coordination_score"
                else:
                    normalized_value = measure
                    normalized_unit = unit
                    
            else:
                # Unknown motor ability
                normalized_value = measure
                normalized_unit = unit
            
            return normalized_value, normalized_unit
        
        # Group by motor ability
        motor_ability_groups = {}
        for item in motor_abilities_data:
            motor_ability = item['motor_ability']
            if motor_ability not in motor_ability_groups:
                motor_ability_groups[motor_ability] = []
            motor_ability_groups[motor_ability].append(item)
        
        normalized_results = []
        
        for motor_ability, exercises in motor_ability_groups.items():
            normalized_values = []
            units = []
            
            for exercise in exercises:
                exercise_name = exercise.get('exercise_name', '')
                measure = float(exercise['measure'])
                unit = exercise['unit']
                
                # Apply motor ability specific normalization with biomechanical indices
                normalized_value, normalized_unit = normalize_by_motor_ability(
                    motor_ability, measure, unit, exercise_name
                )
                
                normalized_values.append(normalized_value)
                units.append(normalized_unit)
            
            if normalized_values:
                # Calculate representative value
                if motor_ability.lower() == 'hitrost':
                    # For speed: higher m/s = better performance
                    representative_value = sum(normalized_values) / len(normalized_values)
                    precision = 2
                elif motor_ability.lower() == 'moč':
                    # For power: higher values = better
                    representative_value = sum(normalized_values) / len(normalized_values)
                    precision = 2
                else:
                    representative_value = sum(normalized_values) / len(normalized_values)
                    precision = 1
                
                most_common_unit = max(set(units), key=units.count) if units else 'units'
                
                normalized_results.append({
                    'motor_ability': motor_ability,
                    'measure': round(representative_value, precision),
                    'unit': most_common_unit,
                    'exercise_count': len(exercises)
                })
        
        return normalized_results
    
    @staticmethod
    def get_motor_ability_analytics_by_athlete(trainer_id, athlete_id):
        """Get normalized motor ability analytics for Slovenian motor abilities"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First verify the athlete belongs to the trainer
            athlete_check_query = """
                SELECT COUNT(*) as count
                FROM trainers_athletes ta
                JOIN users u ON ta.athlete_id = u.id
                WHERE ta.trainer_id = :1 AND ta.athlete_id = :2 AND u.role = 1
            """
            cursor.execute(athlete_check_query, [trainer_id, athlete_id])
            result = cursor.fetchone()
            
            if result[0] == 0:
                raise Exception("Športnik ni dodeljen temu trenerju ali ne obstaja")
            
            log_with_unicode(f"✓ Športnik {athlete_id} pripada trenerju {trainer_id}")
            
            # Get all tests for this athlete and trainer, sorted by test_date
            all_tests_query = """
                SELECT id, test_date
                FROM tests
                WHERE athlete_id = :1 AND trainer_id = :2
                ORDER BY TO_DATE(test_date, 'DD-MON-RR') ASC, id ASC
            """
            
            cursor.execute(all_tests_query, [athlete_id, trainer_id])
            tests_data = cursor.fetchall()
            
            log_with_unicode(f"✓ Najdenih {len(tests_data)} testov za športnika {athlete_id}")
            
            tests = []
            for test_data in tests_data:
                current_test_id = test_data[0]
                current_test_date = test_data[1]
                
                # Get motor abilities with exercise names for proper normalization
                motor_abilities_query = """
                    SELECT 
                        ma.motor_ability,
                        et.measure,
                        et.unit,
                        e.exercise as exercise_name
                    FROM exercises_tests et
                    JOIN exercises e ON et.exercise_id = e.id
                    JOIN methods m ON e.method_id = m.id
                    JOIN motor_abilities ma ON m.motor_ability_id = ma.id
                    WHERE et.test_id = :1
                    ORDER BY ma.motor_ability, e.exercise
                """
                
                cursor.execute(motor_abilities_query, [current_test_id])
                motor_abilities_data = cursor.fetchall()
                
                # Convert to list of dictionaries
                raw_data = []
                for row in motor_abilities_data:
                    raw_data.append({
                        'motor_ability': row[0],
                        'measure': row[1],
                        'unit': row[2],
                        'exercise_name': row[3]
                    })
                
                # Apply Slovenian motor ability normalization
                normalized_motor_abilities = TrainerManager.normalize_motor_ability_values(raw_data)
                
                test_obj = {
                    'id': current_test_id,
                    'test_date': current_test_date,
                    'motor_abilities': normalized_motor_abilities
                }
                tests.append(test_obj)
            
            cursor.close()
            connection.close()
            
            result = {
                'athlete_id': athlete_id,
                'total_tests': len(tests),
                'tests': tests
            }
            
            log_with_unicode(f"✓ Normalizirana analitika za slovenske motorične sposobnosti pripravljena")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju analitike motoričnih sposobnosti: {e}")
            raise

    @staticmethod
    def delete_periodization(trainer_id, periodization_id):
        """Delete a periodization by ID, only if trainer owns it"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # First verify that the periodization belongs to the trainer
            check_query = """
                SELECT COUNT(*) as count
                FROM periodizations
                WHERE id = :1 AND trainer_id = :2
            """
            print(periodization_id, trainer_id)
            cursor.execute(check_query, [periodization_id, trainer_id])
            result = cursor.fetchone()
            
            if result[0] == 0:
                raise Exception(f"Periodizacija z ID {periodization_id} ne obstaja ali ni dodeljena temu trenerju")
            
            # Delete periodization (cascades will handle related data)
            delete_query = "DELETE FROM periodizations WHERE id = :1"
            cursor.execute(delete_query, [periodization_id])
            
            rows_affected = cursor.rowcount
            connection.commit()
            cursor.close()
            connection.close()
            
            if rows_affected > 0:
                success_message = f"Periodizacija z ID {periodization_id} je bila uspešno izbrisana"
                log_with_unicode(f"✓ {success_message}")
                return success_message
            else:
                raise Exception(f"Periodizacija z ID {periodization_id} ni bila najdena")
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri brisanju periodizacije {periodization_id}: {e}")
            raise
    
    @staticmethod
    def get_microcycle_info(microcycle_id, day_of_week_number):
        """Get detailed microcycle information for a specific day"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()

            microcycle_active_rest_query = """
                SELECT active_rest
                FROM microcycles
                WHERE id = :1
            """
            cursor.execute(microcycle_active_rest_query, [microcycle_id])
            active_rest_data = cursor.fetchone()
            if active_rest_data is not None:
                active_rest = bool(active_rest_data[0])
            else:
                active_rest = False
            
            # Get methods for the microcycle on specified day
            methods_query = """
                SELECT DISTINCT
                    m.id AS method_id,
                    m.method_name,
                    m.method_group,
                    m.sets,
                    m.repetitions,
                    m.burden_percentage_of_MVC,
                    m.VO2MAX,
                    m.HRPERCENTAGE,
                    m.rest_seconds,
                    m.duration_min,
                    m.contraction_type,
                    m.tempo,
                    m.motor_ability_id,
                    ma.motor_ability
                FROM methods m
                JOIN exercises e ON m.id = e.method_id
                JOIN exercises_microcycles em ON e.id = em.exercise_id
                JOIN motor_abilities ma ON m.motor_ability_id = ma.id
                WHERE em.microcycle_id = :1
                    AND em.day_of_week_number = :2
                ORDER BY m.id
            """
            
            cursor.execute(methods_query, [microcycle_id, day_of_week_number])
            methods_data = cursor.fetchall()
            
            if not methods_data:
                # Return empty structure if no data found
                return {
                    'microcycle_id': microcycle_id,
                    'day_of_week_number': day_of_week_number,
                    'methods': []
                }
            
            methods = []
            for method_data in methods_data:
                method_id = method_data[0]
                
                # Get exercises for this method on the specified day
                exercises_query = """
                    SELECT 
                        em.exercise_date,
                        em.day_of_week_number,
                        e.id AS exercise_id,
                        e.exercise AS exercise_name,
                        SUBSTR(e.description, 1, 4000) AS description,
                        e.video_url,
                        e.difficulty,
                        em.exercise_finished,
                        TO_CHAR(em.exercise_date, 'Day') AS day_of_week_name
                    FROM exercises_microcycles em
                    JOIN exercises e ON em.exercise_id = e.id
                    WHERE em.microcycle_id = :1
                        AND e.method_id = :2
                        AND em.day_of_week_number = :3
                    ORDER BY em.exercise_date, em.id
                """
                
                cursor.execute(exercises_query, [microcycle_id, method_id, day_of_week_number])
                exercises_data = cursor.fetchall()
                
                exercises = []
                for exercise_data in exercises_data:
                    exercise_obj = {
                        'exercise_date': exercise_data[0].strftime('%Y-%m-%d') if exercise_data[0] else None,
                        'day_of_week_number': exercise_data[1],
                        'exercise_id': exercise_data[2],
                        'exercise_name': exercise_data[3],
                        'description': exercise_data[4],
                        'video_url': exercise_data[5],
                        'difficulty': exercise_data[6],
                        'exercise_finished': bool(exercise_data[7]) if exercise_data[7] is not None else False,
                        'day_of_week_name': exercise_data[8].strip() if exercise_data[8] else None
                    }
                    exercises.append(exercise_obj)
                
                # Helper function to handle None values in calculations
                def safe_math_operation(value, operation_func, default=None):
                    """Safely perform math operations, handling None values"""
                    if value is not None:
                        return operation_func(value)
                    return default
                
                # Build method object with None-safe calculations
                method_obj = {
                    'method_id': method_data[0],
                    'method_name': method_data[1],
                    'method_group': method_data[2],
                    'method_parameters': {
                        'sets': safe_math_operation(
                            method_data[3], 
                            lambda x: math.floor(x/2) if active_rest else x,
                            method_data[3]
                        ),
                        'repetitions': method_data[4],
                        'burden_percentage_of_mvc': safe_math_operation(
                            method_data[5],
                            lambda x: math.floor(x-10) if active_rest else x,
                            method_data[5]
                        ),
                        'vo2_max': safe_math_operation(
                            method_data[6],
                            lambda x: math.floor(x-10) if active_rest else x,
                            method_data[6]
                        ),
                        'hr_percentage': safe_math_operation(
                            method_data[7],
                            lambda x: math.floor(x-10) if active_rest else x,
                            method_data[7]
                        ),
                        'rest_seconds': method_data[8],
                        'duration_min': method_data[9],
                        'contraction_type': method_data[10],
                        'tempo': method_data[11]
                    },
                    'motor_ability_id': method_data[12],
                    'motor_ability': method_data[13],
                    'exercises': exercises
                }
                
                methods.append(method_obj)
            
            cursor.close()
            connection.close()
            
            result = {
                'microcycle_id': microcycle_id,
                'day_of_week_number': day_of_week_number,
                'methods': methods
            }
            
            log_with_unicode(f"✓ Pridobljene informacije za mikrocikel {microcycle_id}, dan {day_of_week_number}")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju informacij o mikrociklu {microcycle_id}: {e}")
            raise Exception(f"Napaka pri pridobivanju informacij o mikrociklu: {str(e)}")


    @staticmethod
    def get_my_athletes(trainer_id):
        """Get all athletes assigned to a specific trainer"""
        try:
            # Get athletes assigned to this trainer
            query = """
                SELECT u.id, u.first_name, u.last_name, u.phone_number, u.email, u.role
                FROM users u
                JOIN trainers_athletes ta ON u.id = ta.athlete_id
                WHERE ta.trainer_id = :1
                AND u.role = 1
                ORDER BY u.last_name, u.first_name
            """
            
            result = db_manager.execute_query(query, [trainer_id])
            
            # Format results with Unicode handling
            from utils import format_user_data
            formatted_athletes = []
            for athlete in result:
                formatted_athlete = format_user_data({
                    'id': athlete['ID'],
                    'first_name': athlete['FIRST_NAME'],
                    'last_name': athlete['LAST_NAME'],
                    'phone_number': athlete['PHONE_NUMBER'],
                    'email': athlete['EMAIL'],
                    'role': athlete['ROLE']
                })
                formatted_athletes.append(formatted_athlete)
            
            log_with_unicode(f"✓ Trener {trainer_id} ima {len(formatted_athletes)} dodeljenih športnikov")
            return formatted_athletes
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju mojih športnikov za trenerja {trainer_id}: {e}")
            raise Exception(f"Napaka pri pridobivanju mojih športnikov: {str(e)}")

    @staticmethod
    def add_athlete(trainer_id, athlete_id):
        """Add an athlete to a trainer's list"""
        try:
            # First, verify the athlete exists and has role 1
            athlete_query = """
                SELECT id, first_name, last_name, role 
                FROM users 
                WHERE id = :1 AND role = 1
            """
            athlete_result = db_manager.execute_query(athlete_query, [athlete_id])
            
            if not athlete_result:
                raise Exception("Športnik s tem ID-jem ne obstaja ali ni športnik")
            
            # Check if relationship already exists
            existing_query = """
                SELECT COUNT(*) as count
                FROM trainers_athletes 
                WHERE trainer_id = :1 AND athlete_id = :2
            """
            existing_result = db_manager.execute_query(existing_query, [trainer_id, athlete_id])
            
            if existing_result[0]['COUNT'] > 0:
                raise Exception("Ta športnik je že dodeljen temu trenerju")
            
            # Check if athlete is already assigned to another trainer
            assigned_query = """
                SELECT t.first_name || ' ' || t.last_name as trainer_name
                FROM trainers_athletes ta
                JOIN users t ON ta.trainer_id = t.id
                WHERE ta.athlete_id = :1
            """
            assigned_result = db_manager.execute_query(assigned_query, [athlete_id])
            
            if assigned_result:
                trainer_name = assigned_result[0]['TRAINER_NAME']
                raise Exception(f"Ta športnik je že dodeljen trenerju: {trainer_name}")
            
            # Insert the trainer-athlete relationship
            insert_query = """
                INSERT INTO trainers_athletes (trainer_id, athlete_id)
                VALUES (:1, :2)
            """
            
            rows_affected = db_manager.execute_dml(insert_query, [trainer_id, athlete_id])
            
            if rows_affected > 0:
                athlete_name = f"{athlete_result[0]['FIRST_NAME']} {athlete_result[0]['LAST_NAME']}"
                log_with_unicode(f"✓ Športnik {athlete_name} (ID: {athlete_id}) uspešno dodeljen trenerju {trainer_id}")
                return {
                    'athlete_id': athlete_id,
                    'athlete_name': athlete_name,
                    'trainer_id': trainer_id
                }
            else:
                raise Exception("Napaka pri dodajanju športnika")
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri dodajanju športnika {athlete_id} trenerju {trainer_id}: {e}")
            raise
    
    @staticmethod
    def create_periodization(athlete_id, trainer_id, difficulty, competition_date, mesocycle_lengths, method_ids, periodization_name):
        """Create a new periodization using Oracle stored procedure"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Prepare PL/SQL block to call the stored procedure
            plsql_block = """
            BEGIN
                PKG_PERIODIZATION_BUILDER.create_periodization(
                    p_athlete_id => :athlete_id,
                    p_trainer_id => :trainer_id,
                    p_difficulty => :difficulty,
                    p_competition_date => TO_DATE(:competition_date, 'YYYY-MM-DD'),
                    p_mesocycle_lengths => :mesocycle_lengths,
                    p_method_ids => :method_ids,
                    p_periodization_name => :periodization_name
                );
            END;
            """
            
            # Execute the PL/SQL block
            cursor.execute(plsql_block, {
                'athlete_id': athlete_id,
                'trainer_id': trainer_id,
                'difficulty': difficulty,
                'competition_date': competition_date,
                'mesocycle_lengths': mesocycle_lengths,
                'method_ids': method_ids,
                'periodization_name': periodization_name
            })
            
            connection.commit()
            cursor.close()
            connection.close()
            
            success_message = f"Periodizacija '{periodization_name}' uspešno ustvarjena za športnika {athlete_id}"
            log_with_unicode(f"✓ {success_message}")
            return success_message
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri ustvarjanju periodizacije: {e}")
            raise Exception(f"Napaka pri ustvarjanju periodizacije: {str(e)}")

    @staticmethod
    def get_methods():
        """Get all methods grouped by motor ability and method group"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Get motor abilities
            motor_abilities_query = """
                SELECT id, motor_ability 
                FROM motor_abilities 
                WHERE NOT motor_ability = 'Gibljivost'
                ORDER BY
                CASE 
                    WHEN motor_ability = 'Moč' THEN 1
                    WHEN motor_ability = 'Vzdržljivost' THEN 2
                    WHEN motor_ability = 'Hitrost' THEN 3
                    ELSE 4
                END,
                motor_ability
            """
            cursor.execute(motor_abilities_query)
            motor_abilities = cursor.fetchall()
            
            result = []
            for ma in motor_abilities:
                motor_ability_id = ma[0]
                motor_ability_name = ma[1]
                
                # Get method groups for this motor ability
                method_groups_query = """
                    SELECT DISTINCT method_group
                    FROM methods
                    WHERE motor_ability_id = :1
                    ORDER BY method_group
                """
                cursor.execute(method_groups_query, [motor_ability_id])
                method_groups = cursor.fetchall()
                
                method_groups_list = []
                for mg in method_groups:
                    method_group_name = mg[0]
                    
                    # Get methods for this group
                    methods_query = """
                        SELECT id, method_name, description
                        FROM methods
                        WHERE motor_ability_id = :1
                          AND method_group = :2
                        ORDER BY method_name
                    """
                    cursor.execute(methods_query, [motor_ability_id, method_group_name])
                    methods = cursor.fetchall()
                    
                    methods_list = []
                    for method in methods:
                        methods_list.append({
                            'id': method[0],
                            'name': method[1],
                            'description': method[2]
                        })
                    
                    method_groups_list.append({
                        'group_name': method_group_name,
                        'methods': methods_list
                    })
                
                result.append({
                    'motor_ability': motor_ability_name,
                    'method_groups': method_groups_list
                })
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Pridobljene metode razvrščene po motoričnih sposobnostih")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju metod: {e}")
            raise Exception(f"Napaka pri pridobivanju metod: {str(e)}")