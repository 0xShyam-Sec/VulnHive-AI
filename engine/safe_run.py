"""The one boundary that owns the producer error policy.

- Fatal errors bubble up (scan stops).
- All other exceptions are caught, logged, and recorded as a ScanError
  with kind='producer_fatal'. Other producers continue.
"""

from __future__ import annotations

import traceback
from typing import AsyncIterator

from engine.errors import FatalError, ScanError
from engine.finding_model import Finding
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext

_log = get_logger()


async def safe_produce(producer: FindingProducer, ctx: ScanContext) -> AsyncIterator[Finding]:
    """Wrap producer.produce(ctx) with the error policy."""
    try:
        async for finding in producer.produce(ctx):
            yield finding
    except FatalError:
        raise
    except Exception as e:
        _log.error(
            "producer_failed",
            producer=producer.name,
            scan_id=ctx.scan_id,
            error=str(e),
        )
        ctx.record_error(ScanError(
            scan_id=ctx.scan_id,
            producer=producer.name,
            phase=producer.phase,
            kind="producer_fatal",
            error=str(e),
            traceback=traceback.format_exc(),
        ))
