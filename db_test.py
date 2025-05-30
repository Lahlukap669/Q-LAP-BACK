import oracledb
from flask import Flask, jsonify
import os

app = Flask(__name__)
oracledb.defaults.fetch_lobs = False

# Database configuration
DB_USER = "ADMIN"  # Replace with your DB username
DB_PASSWORD = ""  # Replace with your DB password

# TLS connection string (replace with your actual connection string from step 3)
DB_URL = """(description= (retry_count=20)(retry_delay=3)(address=(protocol=tcps)(port=1522)(host=adb.eu-frankfurt-1.oraclecloud.com))(connect_data=(service_name=gc5119dfb84e0ef_atp_high.adb.oraclecloud.com))(security=(ssl_server_dn_match=yes)))"""

app.config['JSON_AS_ASCII'] = False
import json
def decode_unicode_escapes(text):
    """Decode literal Unicode escape sequences to actual characters"""
    if isinstance(text, str) and '\\u' in text:
        try:
            # Use JSON decode to handle Unicode escape sequences
            return json.loads(f'"{text}"')
        except Exception:
            return text
    return text

@app.route('/motor_abilities')
def get_motor_abilities():
    try:
        connection = oracledb.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            dsn=DB_URL
        )
        
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM motor_abilities")
        
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        
        result = []
        for row in rows:
            row_dict = {}
            for i, value in enumerate(row):
                column_name = columns[i]
                # Apply Unicode decoding to all values
                row_dict[column_name] = decode_unicode_escapes(value)
            result.append(row_dict)
        
        cursor.close()
        connection.close()
        
        response_data = {
            "status": "success",
            "data": result,
            "count": len(result)
        }
        
        # Create explicit response with UTF-8 encoding
        return app.response_class(
            response=json.dumps(response_data, ensure_ascii=False, indent=2),
            status=200,
            mimetype='application/json; charset=utf-8'
        )
        
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route('/health')
def health_check():
    try:
        connection = oracledb.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            dsn=DB_URL
        )
        connection.close()
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
