"""Map producer name → factory. The single place that knows how to instantiate one.

`engine/modes.py` references producers by string. `engine/runner.py` is given
ready-made FindingProducer instances. This file is the bridge.
"""

from __future__ import annotations

from typing import Callable

from engine.producer import FindingProducer
from engine.modes import build_producer_names


# Lazy-imported factories so that pulling a single producer doesn't drag in
# the entire agent zoo at startup.


def _vuln(module_path: str, class_name: str, vuln_type: str, agent_name: str):
    """Build a VulnAgentProducer by importing the class lazily."""
    import importlib
    from engine.producers.vuln_agent import VulnAgentProducer
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    return VulnAgentProducer(cls, vuln_type=vuln_type, agent_name=agent_name)


def _sqli():            return _vuln("agents.vuln.sqli",            "SQLiAgent",           "sqli",            "SQLiAgent")
def _xss():             return _vuln("agents.vuln.xss",             "XSSAgent",            "xss",             "XSSAgent")
def _csrf():            return _vuln("agents.vuln.csrf",            "CSRFAgent",           "csrf",            "CSRFAgent")
def _ssrf():            return _vuln("agents.vuln.ssrf",            "SSRFAgent",           "ssrf",            "SSRFAgent")
def _idor():            return _vuln("agents.vuln.idor",            "IDORAgent",           "idor",            "IDORAgent")
def _idor_advanced():   return _vuln("agents.vuln.idor_advanced",   "IDORAdvancedAgent",   "idor",            "IDORAdvancedAgent")
def _cmdi():            return _vuln("agents.vuln.cmdi",            "CMDIAgent",           "command_injection", "CMDIAgent")
def _ssti():            return _vuln("agents.vuln.ssti",            "SSTIAgent",           "ssti",            "SSTIAgent")
def _xxe():             return _vuln("agents.vuln.xxe",             "XXEAgent",            "xxe",             "XXEAgent")
def _jwt():             return _vuln("agents.vuln.jwt",             "JWTAgent",            "jwt",             "JWTAgent")
def _path_traversal():  return _vuln("agents.vuln.path_traversal",  "PathTraversalAgent",  "path_traversal",  "PathTraversalAgent")
def _file_upload():     return _vuln("agents.vuln.file_upload",     "FileUploadAgent",     "file_upload",     "FileUploadAgent")
def _graphql():         return _vuln("agents.vuln.graphql",         "GraphQLAgent",        "graphql",         "GraphQLAgent")
def _http_smuggling():  return _vuln("agents.vuln.http_smuggling",  "HTTPSmugglingAgent",  "http_smuggling",  "HTTPSmugglingAgent")
def _headers():         return _vuln("agents.vuln.headers",         "HeadersAgent",        "security_headers", "HeadersAgent")
def _sensitive_data():  return _vuln("agents.vuln.sensitive_data",  "SensitiveDataAgent",  "sensitive_data",  "SensitiveDataAgent")
def _mass_assignment(): return _vuln("agents.vuln.mass_assignment", "MassAssignmentAgent", "mass_assignment", "MassAssignmentAgent")
def _open_redirect():   return _vuln("agents.vuln.open_redirect",   "OpenRedirectAgent",   "open_redirect",   "OpenRedirectAgent")
def _cache_poison():    return _vuln("agents.vuln.cache_poison",    "CachePoisonAgent",    "cache_poison",    "CachePoisonAgent")
def _auth_bypass():     return _vuln("agents.vuln.auth_bypass",     "AuthBypassAgent",     "auth_bypass",     "AuthBypassAgent")
def _business_logic():  return _vuln("agents.vuln.business_logic",  "BusinessLogicAgent",  "business_logic",  "BusinessLogicAgent")
def _subdomain():       return _vuln("agents.vuln.subdomain",       "SubdomainAgent",      "subdomain",       "SubdomainAgent")
def _websocket():       return _vuln("agents.vuln.websocket",       "WebSocketAgent",      "websocket",       "WebSocketAgent")
def _api_version():     return _vuln("agents.vuln.api_version",     "APIVersionAgent",     "api_version",     "APIVersionAgent")
def _rate_limit():      return _vuln("agents.vuln.rate_limit",      "RateLimitAgent",      "rate_limit",      "RateLimitAgent")


def _passive_recon():
    from engine.producers.passive_recon import PassiveReconProducer
    return PassiveReconProducer()


def _playwright_crawler():
    from engine.producers.playwright_crawler import PlaywrightProducer
    return PlaywrightProducer()


def _nuclei():
    from engine.producers.nuclei import NucleiProducer
    return NucleiProducer()


def _nmap():
    from engine.producers.nmap import NmapProducer
    return NmapProducer()


def _shodan():
    from engine.producers.shodan import ShodanProducer
    return ShodanProducer()


def _waf_detector():
    """waf_detector is currently a non-finding-emitting module; return a no-op producer."""
    class _NullProducer(FindingProducer):
        name = "waf_detector"
        phase = "discovery"
        async def produce(self, ctx):
            if False:
                yield
    return _NullProducer()


def _systematic():
    class _NullProducer(FindingProducer):
        name = "systematic"
        phase = "attack"
        async def produce(self, ctx):
            if False:
                yield
    return _NullProducer()


def _openapi_importer():
    class _NullProducer(FindingProducer):
        name = "openapi_importer"
        phase = "discovery"
        async def produce(self, ctx):
            if False:
                yield
    return _NullProducer()


PRODUCER_FACTORIES: dict[str, Callable[[], FindingProducer]] = {
    # discovery / recon
    "passive_recon":      _passive_recon,
    "playwright_crawler": _playwright_crawler,
    "nuclei":             _nuclei,
    "nmap":               _nmap,
    "shodan":             _shodan,
    "waf_detector":       _waf_detector,
    "systematic":         _systematic,
    "openapi_importer":   _openapi_importer,

    # vuln agents
    "sqli":            _sqli,
    "xss":             _xss,
    "csrf":            _csrf,
    "ssrf":            _ssrf,
    "idor":            _idor,
    "idor_advanced":   _idor_advanced,
    "cmdi":            _cmdi,
    "ssti":            _ssti,
    "xxe":             _xxe,
    "jwt":             _jwt,
    "path_traversal":  _path_traversal,
    "file_upload":     _file_upload,
    "graphql":         _graphql,
    "http_smuggling":  _http_smuggling,
    "headers":         _headers,
    "sensitive_data":  _sensitive_data,
    "mass_assignment": _mass_assignment,
    "open_redirect":   _open_redirect,
    "cache_poison":    _cache_poison,
    "auth_bypass":     _auth_bypass,
    "business_logic":  _business_logic,
    "subdomain":       _subdomain,
    "websocket":       _websocket,
    "api_version":     _api_version,
    "rate_limit":      _rate_limit,
}


def build_producer(name: str) -> FindingProducer:
    if name not in PRODUCER_FACTORIES:
        raise KeyError(f"no producer factory for {name!r}")
    return PRODUCER_FACTORIES[name]()


def build_producers(mode: str) -> list[FindingProducer]:
    """Return ready-made FindingProducer instances for a mode."""
    return [build_producer(n) for n in build_producer_names(mode)]
