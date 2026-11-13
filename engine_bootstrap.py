"""Source-engine entry point with direct model-call policy installed before SDK imports."""
import json
import os
from pathlib import Path
import sys

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')
os.environ.setdefault('TIKTOKEN_CACHE_DIR', '/opt/tokenizer-cache')
sys.path.insert(0, '/opt/strix-engine')

import model_calls
import model_failover
import model_guard

if not any(flag in sys.argv for flag in ('--help', '--version')):
    router = None
    guard = None
    path = os.environ.get('STRIX_MODEL_FAILOVER_FILE')
    if path:
        try:
            config = json.loads(Path(path).read_text(encoding='utf-8'))
            router = model_failover.Router(config, config['state_dir'], Path.cwd() / 'model_route.json')
            threshold = int(config.get('pause_after_failures') or 0)
            if threshold > 0:
                guard = model_guard.Guard(Path.cwd(), threshold)
        except Exception as error:  # noqa: BLE001 - a broken optional file must not block scans
            print(f'[模型调用] 主备模型配置读取失败（{type(error).__name__}），仅使用主模型。', flush=True)
            router = None
            guard = None
    model_calls.install_httpx(Path.cwd(), router, guard)
from strix.interface.main import main

main()
