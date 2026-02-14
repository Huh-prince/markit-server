from fastapi import FastAPI
from fastapi.responses import RedirectResponse
import subprocess
import os
import signal
import sys
import time

# Start Node.js server as subprocess
node_process = None

def start_node():
    global node_process
    env = os.environ.copy()
    env['PORT'] = '8001'
    node_process = subprocess.Popen(
        ['node', 'server.js'],
        cwd='/app/backend',
        env=env,
        stdout=sys.stdout,
        stderr=sys.stderr
    )

def stop_node(signum=None, frame=None):
    global node_process
    if node_process:
        node_process.terminate()
        node_process.wait()
    sys.exit(0)

signal.signal(signal.SIGTERM, stop_node)
signal.signal(signal.SIGINT, stop_node)

start_node()

# Keep the process running
while True:
    if node_process.poll() is not None:
        # Node process died, restart it
        start_node()
    time.sleep(1)
