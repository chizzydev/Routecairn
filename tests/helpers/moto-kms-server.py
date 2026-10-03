"""Moto's AWS backend behind a WSGI adapter that removes duplicate Date headers.

Werkzeug generates its own Date header. Keeping Moto's additional Date header
poisons clock-skew calculation in current AWS SDKs. Cryptographic behavior is Moto's.
"""
import sys
from moto.server import DomainDispatcherApplication, create_backend_app
from werkzeug.serving import run_simple

application = DomainDispatcherApplication(create_backend_app)

def one_date(environ, start_response):
    def headers(status, values, exc_info=None):
        return start_response(status, [(key, value) for key, value in values if key.lower() != "date"], exc_info)
    return application(environ, headers)

run_simple("127.0.0.1", int(sys.argv[1]), one_date, threaded=True)
