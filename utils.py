import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

def decode_unicode_escapes(text):
    """Decode literal Unicode escape sequences to actual characters"""
    if isinstance(text, str) and '\\u' in text:
        try:
            # Use JSON decode to handle Unicode escape sequences
            return json.loads(f'"{text}"')
        except Exception:
            return text
    return text

def format_database_row(row_data: tuple, columns: list) -> dict:
    """Convert database row tuple to dictionary with Unicode handling"""
    row_dict = {}
    for i, value in enumerate(row_data):
        column_name = columns[i]
        # Apply Unicode decoding to all string values
        if isinstance(value, str):
            row_dict[column_name] = decode_unicode_escapes(value)
        else:
            row_dict[column_name] = value
    return row_dict

def format_database_results(rows: List[tuple], columns: list) -> List[dict]:
    """Convert multiple database rows to list of dictionaries with Unicode handling"""
    result = []
    for row in rows:
        formatted_row = format_database_row(row, columns)
        result.append(formatted_row)
    return result

def create_json_response(app, data: Any, status_code: int = 200) -> Any:
    """Create Flask response with proper UTF-8 encoding for Slovenian characters"""
    return app.response_class(
        response=json.dumps(data, ensure_ascii=False, indent=2, default=str),
        status=status_code,
        mimetype='application/json; charset=utf-8'
    )

def validate_slovenian_text(text: str) -> bool:
    """Validate if text contains valid Slovenian characters"""
    if not text:
        return False
    
    # Allow Slovenian characters: č, ž, š, đ, ć and their uppercase versions
    slovenian_pattern = r'^[a-zA-ZčžšđćČŽŠĐĆ\s\-\.\_\d]+$'
    return bool(re.match(slovenian_pattern, text))

def sanitize_input(text: str) -> str:
    """Sanitize input while preserving Slovenian characters"""
    if not text:
        return ""
    
    # Remove potentially dangerous characters but keep Slovenian ones
    # Allow letters (including Slovenian), numbers, spaces, and basic punctuation
    sanitized = re.sub(r'[^\w\sčžšđćČŽŠĐĆ\.\-\_@]', '', text)
    return sanitized.strip()

def format_user_data(user_data: Dict) -> Dict:
    """Format user data with proper Unicode handling"""
    if not user_data:
        return {}
    
    formatted_data = {}
    for key, value in user_data.items():
        if isinstance(value, str):
            formatted_data[key] = decode_unicode_escapes(value)
        else:
            formatted_data[key] = value
    
    return formatted_data

def log_with_unicode(message: str) -> None:
    """Print log message with proper Unicode support"""
    try:
        print(message.encode('utf-8').decode('utf-8'))
    except:
        print(message)
