from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from database import db_manager
from utils import format_user_data, sanitize_input, log_with_unicode
import oracledb
from datetime import timedelta

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