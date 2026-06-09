"""Importer: parse Nmap XML and yield one Finding per open port."""

from __future__ import annotations

import asyncio
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import AsyncIterator, Optional

from engine.finding_model import Confidence, Finding, Severity
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance

_log = get_logger()


class NmapProducer(FindingProducer):
    name = "nmap"
    phase = "discovery"

    def __init__(self, xml_path: Optional[Path] = None, nmap_bin: str = "nmap",
                 args: tuple = ("-sV", "-Pn", "--top-ports", "200")):
        self.xml_path = Path(xml_path) if xml_path else None
        self.nmap_bin = nmap_bin
        self.args = args

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if self.xml_path is None:
            self.xml_path = await self._run_live(ctx)
        if self.xml_path is None or not self.xml_path.exists():
            return

        try:
            tree = ET.parse(self.xml_path)
        except ET.ParseError as e:
            _log.warning("nmap_xml_parse_failed", error=str(e))
            return

        for host in tree.getroot().findall("host"):
            if ctx.cancelled:
                break
            addr_el = host.find("address")
            host_addr = addr_el.get("addr") if addr_el is not None else ctx.target
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port.get("portid"))
                proto = port.get("protocol")
                svc = port.find("service")
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                name = svc.get("name", "") if svc is not None else ""

                title_bits = [s for s in [product, version] if s]
                title = " ".join(title_bits) or f"{name} {port_num}/{proto}"
                rule_id = f"nmap:port-{port_num}-{name or 'unknown'}"

                f = Finding(
                    scan_id=ctx.scan_id,
                    rule_id=rule_id,
                    vuln_type="open_port",
                    title=f"Open port {port_num}/{proto}: {title}".strip(),
                    cwe=200,
                    cvss=3.7,
                    severity=Severity.info,
                    confidence=Confidence.confirmed,
                    primary_evidence=f"{host_addr}:{port_num} {proto} {name} {product} {version}".strip(),
                    references_json={
                        "host": host_addr,
                        "port": port_num,
                        "protocol": proto,
                        "service": name,
                        "product": product,
                        "version": version,
                    },
                )
                yield attach_instance(
                    f,
                    url=f"{proto}://{host_addr}:{port_num}",
                    method=proto.upper(),
                    evidence_raw=f.primary_evidence,
                    source_tool="nmap",
                )

    async def _run_live(self, ctx: ScanContext) -> Optional[Path]:
        out = Path(tempfile.mktemp(suffix=".xml", prefix="nmap-"))
        cmd = [self.nmap_bin, *self.args, "-oX", str(out), ctx.target]
        loop = asyncio.get_running_loop()
        try:
            proc = await loop.run_in_executor(None,
                lambda: subprocess.run(cmd, capture_output=True, timeout=600))
            if proc.returncode != 0:
                _log.warning("nmap_returned_nonzero", code=proc.returncode)
            return out if out.exists() else None
        except FileNotFoundError:
            _log.warning("nmap_binary_missing", bin=self.nmap_bin)
            return None
        except Exception as e:
            _log.warning("nmap_invocation_failed", error=str(e))
            return None
