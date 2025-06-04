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