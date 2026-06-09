from engine.classification import classify, CWE_DEFAULTS, CVSS_DEFAULTS  # noqa: F401


def test_known_vuln_type_maps_to_cwe_and_cvss():
    cwe, cvss = classify("sqli")
    assert cwe == 89
    assert 7.0 <= cvss <= 10.0


def test_unknown_vuln_type_returns_none_none():
    cwe, cvss = classify("definitely_not_a_vuln_type")
    assert cwe is None
    assert cvss is None


def test_missing_header_is_lower_severity():
    cwe, cvss = classify("missing_security_header")
    assert cwe == 693
    assert cvss is not None and cvss < 6.0
