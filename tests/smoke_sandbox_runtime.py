"""Exercise the real sandbox SDK and private bridge connection without a model."""
import asyncio
import os
import sys
import uuid
sys.path.insert(0,'/opt/strix-engine')
from strix.runtime import session_manager

async def check():
    identifier='sdk-smoke-'+uuid.uuid4().hex
    try:
        bundle=await asyncio.wait_for(session_manager.create_or_reuse(identifier,
            image='ghcr.io/usestrix/strix-sandbox:1.3.0',local_sources=[],
            status_sink=lambda phase:print(phase,flush=True)),90)
        session=bundle['session']
        result=await session.exec('printf','sandbox-exec-ok',timeout=15,shell=False)
        stdout=result.stdout.decode() if isinstance(result.stdout,bytes) else result.stdout
        assert result.ok() and stdout=='sandbox-exec-ok',(stdout,result.stderr)
        endpoint=await session.resolve_exposed_port(48080)
        assert endpoint.host!='127.0.0.1',endpoint
        await asyncio.wait_for(bundle['caido_client'].get(),90)
        print('SANDBOX SDK AND PRIVATE BRIDGE SMOKE PASSED',flush=True)
    finally:
        await session_manager.cleanup(identifier)

asyncio.run(check())
