from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from database import db_manager
from utils import format_user_data, sanitize_input, log_with_unicode
import oracledb
from datetime import timedelta

class UserManager:
    @staticmethod
    def register_user(first_name, last_name, phone_number, email, password, role):
        """Register a new user using Oracle stored procedure"""
        try:
            # Sanitize inputs while preserving Slovenian characters
            first_name = sanitize_input(first_name)
            last_name = sanitize_input(last_name)
            phone_number = sanitize_input(phone_number)
            email = sanitize_input(email.lower())
            
            # Call Oracle stored procedure - NO password hashing in Python
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Create output variable for returned user ID
            user_id_var = cursor.var(oracledb.NUMBER)
            
            # Call the stored procedure
            cursor.callproc('PKG_USER_MANAGEMENT.register_user', [
                first_name, last_name, phone_number, 
                email, password, role, user_id_var
            ])
            
            user_id = user_id_var.getvalue()
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Uporabnik uspešno registriran - ID: {user_id}")
            return user_id
                
        except oracledb.DatabaseError as e:
            error_obj, = e.args
            log_with_unicode(f"✗ Napaka pri registraciji: {error_obj.message}")
            
            # Handle specific Oracle errors
            if "ORA-20001" in str(e):
                raise Exception("Vsa polja so obvezna za registracijo")
            elif "ORA-20002" in str(e):
                raise Exception("Uporabnik s tem e-poštnim naslovom že obstaja")
            elif "ORA-20003" in str(e):
                raise Exception("Neveljavna vloga. Uporabite 1 za športnika, 2 za trenerja")
            else:
                raise Exception("Napaka pri registraciji uporabnika")
        except Exception as e:
            log_with_unicode(f"✗ Splošna napaka pri registraciji: {e}")
            raise

    @staticmethod
    def login_user(email, password):
        """Authenticate user using Oracle stored procedure"""
        try:
            email = sanitize_input(email.lower())
            
            # Call Oracle login function - NO password verification in Python
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Call the login function
            user_id = cursor.callfunc('PKG_USER_MANAGEMENT.login', oracledb.NUMBER, [email, password])
            
            if user_id is None:
                log_with_unicode(f"✗ Neuspešna prijava: {email}")
                cursor.close()
                connection.close()
                return None
            
            # Get user details using the stored procedure
            user_cursor = cursor.callfunc('PKG_USER_MANAGEMENT.get_user_details', oracledb.CURSOR, [user_id])
            
            user_data = user_cursor.fetchone()
            user_cursor.close()
            
            if not user_data:
                log_with_unicode(f"✗ Uporabnik ni najden po prijavi: {user_id}")
                cursor.close()
                connection.close()
                return None
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Uspešna prijava: {email}")
            
            # Format user data with Unicode handling
            formatted_user = format_user_data({
                'id': user_data[0],           # id
                'first_name': user_data[1],   # first_name
                'last_name': user_data[2],    # last_name
                'phone_number': user_data[3], # phone_number
                'email': user_data[4],        # email
                'role': user_data[5]          # role
            })
            
            return formatted_user
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri prijavi: {e}")
            raise

    @staticmethod
    def get_user_by_id(user_id):
        """Get user details by ID using Oracle stored procedure"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Call the stored procedure to get user details
            user_cursor = cursor.callfunc('PKG_USER_MANAGEMENT.get_user_details', oracledb.CURSOR, [user_id])
            
            user_data = user_cursor.fetchone()
            user_cursor.close()
            cursor.close()
            connection.close()
            
            if user_data:
                formatted_user = format_user_data({
                    'id': user_data[0],           # id
                    'first_name': user_data[1],   # first_name
                    'last_name': user_data[2],    # last_name
                    'phone_number': user_data[3], # phone_number
                    'email': user_data[4],        # email
                    'role': user_data[5]          # role
                })
                return formatted_user
            return None
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri pridobivanju uporabnika {user_id}: {e}")
            raise

    @staticmethod
    def update_user(user_id, update_data):
        """Update user data using Oracle stored procedure (basic info only)"""
        try:
            # Sanitize inputs
            sanitized_data = {}
            for key, value in update_data.items():
                if isinstance(value, str) and key != 'password':
                    sanitized_data[key] = sanitize_input(value)
                else:
                    sanitized_data[key] = value
            
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Use the basic info update version (4 parameters)
            if all(key in sanitized_data for key in ['first_name', 'last_name', 'phone_number', 'email']):
                cursor.callproc('PKG_USER_MANAGEMENT.update_user', [
                    user_id,
                    sanitized_data['first_name'],
                    sanitized_data['last_name'],
                    sanitized_data['phone_number'],
                    sanitized_data['email']
                ])
                log_with_unicode(f"✓ Osnovni podatki uporabnika {user_id} uspešno posodobljeni")
            else:
                raise Exception("Manjkajo obvezni podatki za posodobitev")
            
            cursor.close()
            connection.close()
            return True
                
        except oracledb.DatabaseError as e:
            error_obj, = e.args
            log_with_unicode(f"✗ Napaka pri posodabljanju uporabnika {user_id}: {error_obj.message}")
            
            # Handle specific Oracle errors
            if "ORA-20002" in str(e):
                raise Exception("E-poštni naslov že obstaja za drugega uporabnika")
            elif "ORA-20004" in str(e):
                raise Exception("Uporabnik ni najden")
            else:
                raise Exception("Napaka pri posodabljanju podatkov")
        except Exception as e:
            log_with_unicode(f"✗ Splošna napaka pri posodabljanju uporabnika {user_id}: {e}")
            raise

    @staticmethod
    def update_user_password(user_id, new_password):
        """Update user password using Oracle stored procedure"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Use the password-only update version (2 parameters)
            cursor.callproc('PKG_USER_MANAGEMENT.update_user', [user_id, new_password])
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Geslo uporabnika {user_id} uspešno posodobljeno")
            return True
                
        except oracledb.DatabaseError as e:
            error_obj, = e.args
            log_with_unicode(f"✗ Napaka pri posodabljanju gesla {user_id}: {error_obj.message}")
            
            # Handle specific Oracle errors
            if "ORA-20004" in str(e):
                raise Exception("Uporabnik ni najden")
            elif "ORA-20005" in str(e):
                raise Exception("Geslo mora imeti vsaj 6 znakov")
            else:
                raise Exception("Napaka pri posodabljanju gesla")
        except Exception as e:
            log_with_unicode(f"✗ Splošna napaka pri posodabljanju gesla {user_id}: {e}")
            raise

    @staticmethod
    def check_email_exists(email):
        """Check if email exists using Oracle stored procedure"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Call the email_exists function
            exists = cursor.callfunc('PKG_USER_MANAGEMENT.email_exists', oracledb.BOOLEAN, [email])
            
            cursor.close()
            connection.close()
            
            return exists
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri preverjanju e-pošte: {e}")
            return False

    @staticmethod
    def check_user_exists(user_id):
        """Check if user exists using Oracle stored procedure"""
        try:
            connection = db_manager.get_connection()
            cursor = connection.cursor()
            
            # Call the user_exists function
            exists = cursor.callfunc('PKG_USER_MANAGEMENT.user_exists', oracledb.BOOLEAN, [user_id])
            
            cursor.close()
            connection.close()
            
            return exists
                
        except Exception as e:
            log_with_unicode(f"✗ Napaka pri preverjanju uporabnika: {e}")
            return False
