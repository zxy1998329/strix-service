"""Only for the isolated local Docker network. No published host port."""
from app import Handler, HTTPServer

HTTPServer(('0.0.0.0', 8765), Handler).serve_forever()
