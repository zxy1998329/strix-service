"""Run the web API and serial worker from one deployable image."""
import os
import signal
import subprocess
import time

children = []
stopping = False


def stop(*_):
    global stopping
    stopping = True
    for child in children:
        if child.poll() is None:
            child.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    children.append(subprocess.Popen(['uvicorn', 'service:app', '--host', os.environ.get('WEB_BIND', '0.0.0.0'),
                                     '--port', os.environ.get('PORT', '8080'), '--no-access-log', '--proxy-headers', '--forwarded-allow-ips', '127.0.0.1']))
    children.append(subprocess.Popen(['python', 'worker.py']))
    while not stopping and all(child.poll() is None for child in children):
        time.sleep(1)
finally:
    stop()
    for child in children:
        try:
            child.wait(timeout=40)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
