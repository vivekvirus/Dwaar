"""The model boundary: a hard 15-second budget around every provider call, in a worker thread with NO database handle.

REQ: AI-SYS-01 (provider adapter in a restricted worker boundary, never on the gate control path), AI-SYS-06 / NFR-13 (timeout 15 s ->
the ordinary UI), PRD 10.1 ('model boundary: untrusted-content sandbox; no credentials; no arbitrary URLs or SQL').

HONEST SCOPE: this is a LOGICAL boundary inside the API process: a worker thread that is handed one immutable ``ProviderRequest`` (server
instruction + sanitised, redacted data) and nothing else - no connection, no session, no file handle, no tools. It is NOT an OS sandbox
and not a separate network namespace; a real deployment should run the gateway worker as its own process with egress limited to the provider
host. The gate control path never imports this package (``services/edge`` has no dependency on it; a test pins that).
A thread that overruns the budget is abandoned (its result is discarded); the HTTP client's own timeout (15 s) bounds the leak.
"""

from __future__ import annotations

import concurrent.futures
import threading

from .providers.base import Provider, ProviderError
from .types import ProviderRequest, ProviderResponse

_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="dwaar-ai-boundary")
_lock = threading.Lock()


def call_provider(
    provider: Provider, request: ProviderRequest, timeout_seconds: float
) -> ProviderResponse:
    future = _POOL.submit(provider.complete, request)
    try:
        return future.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise ProviderError("timeout") from None
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("error") from None
