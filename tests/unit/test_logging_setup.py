import json

from engine.logging_setup import configure_logging, get_logger


def test_get_logger_returns_structlog_logger():
    configure_logging(scan_id=None, log_dir=None, redis_client=None)
    log = get_logger()
    assert hasattr(log, "info")
    assert hasattr(log, "warning")
    assert hasattr(log, "error")


def test_file_sink_writes_jsonl(tmp_path):
    log_dir = tmp_path / "logs"
    configure_logging(scan_id=99, log_dir=log_dir, redis_client=None)
    log = get_logger()
    log.info("phase_start", phase="recon")

    file_path = log_dir / "scan_99.jsonl"
    assert file_path.exists()
    line = file_path.read_text().strip().splitlines()[0]
    payload = json.loads(line)
    assert payload["event"] == "phase_start"
    assert payload["phase"] == "recon"
