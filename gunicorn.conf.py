import multiprocessing
import os

bind = f"0.0.0.0:{int(os.getenv('FLASK_RUN_PORT', '8000'))}"
workers = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count()))
threads = int(os.getenv('GUNICORN_THREADS', '4'))
worker_class = 'gthread'
timeout = int(os.getenv('GUNICORN_TIMEOUT', '60'))
keepalive = 2
accesslog = '-'
errorlog = '-'
loglevel = 'info'
