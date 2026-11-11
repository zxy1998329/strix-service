"""Source-engine entry point with direct model-call policy installed before SDK imports."""
import os
from pathlib import Path
import sys

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')
os.environ.setdefault('TIKTOKEN_CACHE_DIR', '/opt/tokenizer-cache')
sys.path.insert(0, '/opt/strix-engine')

import model_calls

if not any(flag in sys.argv for flag in ('--help', '--version')):
    model_calls.install_httpx(Path.cwd())
from strix.interface.main import main

main()
