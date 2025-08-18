from functools import wraps
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from auth import UserManager
from utils import log_with_unicode

def role_required(*allowed_roles):
    """Decorator to check user roles with Unicode support"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                current_user_id = int(get_jwt_identity())
                user = UserManager.get_user_by_id(current_user_id)
                
                if not user:
                    return jsonify({'message': 'Uporabnik ni najden'}), 404
                
                if user['role'] not in allowed_roles:
                    log_with_unicode(f"✗ Dostop zavrnjen - vloga {user['role']} ni v {allowed_roles}")
                    return jsonify({'message': 'Nezadostne pravice'}), 403
                
                log_with_unicode(f"✓ Dostop odobren - vloga {user['role']}")
                return f(*args, **kwargs)
            except Exception as e:
                log_with_unicode(f"✗ Napaka pri avtorizaciji: {e}")
                return jsonify({'message': 'Napaka pri avtorizaciji'}), 500
        
        return decorated_function
    return decorator

# Role constants (updated to match Oracle package expectations)
ADMIN = 0    # You may need to add admin role to Oracle package
ATHLETE = 1  # Matches Oracle package
TRAINER = 2  # Matches Oracle package
