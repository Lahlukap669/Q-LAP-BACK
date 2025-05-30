def setup_logging(app):
    print("✓ Simple logging initialized")
    return app.logger

def log_request_data():
    from flask import request, g
    from datetime import datetime
    g.request_data = {
        'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
        'endpoint': request.endpoint,
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat()
    }

def log_response_data(response):
    from flask import g
    if hasattr(g, 'request_data'):
        g.request_data['status_code'] = response.status_code
    return response
