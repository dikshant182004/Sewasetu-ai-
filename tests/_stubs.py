"""Lets the unit tests import app.py on a machine that lacks the database / PDF libraries.

Inside the portal's Docker image the real libraries exist and nothing is stubbed.
"""
import sys
from unittest import mock

# The handout pins Flask 2.2.5 but not Werkzeug, so the image gets a Werkzeug (3.1+) that no
# longer has __version__, which Flask 2.2's test client reads. Test-only shim; the portal
# itself does not use the test client.
import werkzeug
if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3"

for _name in ("psycopg2", "psycopg2.errors", "fpdf", "requests"):
    try:
        __import__(_name)
    except ImportError:
        sys.modules[_name] = mock.MagicMock(name=_name)

if isinstance(sys.modules["psycopg2.errors"], mock.MagicMock):
    class UniqueViolation(Exception):
        pass
    sys.modules["psycopg2.errors"].UniqueViolation = UniqueViolation
    sys.modules["psycopg2"].errors = sys.modules["psycopg2.errors"]
