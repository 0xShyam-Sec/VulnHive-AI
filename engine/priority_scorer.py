"""Signal-based endpoint prioritization — score 0-100, higher = test first."""
from engine.scan_state import Endpoint


# Signal keywords for priority detection
HIGH_PRIORITY_PARAMS = {
    'id', 'user_id', 'account_id', 'order_id', 'email', 'username',
    'role', 'admin', 'token', 'password', 'redirect', 'url', 'callback'
}

HIGH_PRIORITY_PATHS = {
    '/admin', '/internal', '/debug', '/upload', '/download', '/config',
    '/settings', '/profile', '/account', '/login', '/auth', '/token',
    '/payment', '/checkout', '/graphql'
}

STATIC_EXTENSIONS = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map'
}

STATIC_PATHS = {'/health', '/ping', '/status', '/static/'}

SENSITIVE_HEADERS = {
    'server', 'x-powered-by', 'x-debug', 'x-aspnet-version',
    'x-runtime-version', 'x-application-context'
}


def score_endpoint(endpoint: Endpoint) -> float:
    """Score an endpoint from 0-100, higher = test first.

    Scoring logic:
    - Base score: 30
    - State-changing methods (POST, PUT, PATCH, DELETE): +15
    - High-priority params (id, user_id, etc.): +20
    - High-priority paths (/admin, /internal, etc.): +15
    - Param count bonus: min(param_count * 3, 15)
    - Sensitive response headers: +5 each
    - Static/CDN assets: -25
    - No params + GET: -10

    Args:
        endpoint: Endpoint dataclass instance

    Returns:
        float: Priority score (0-100)
    """
    score = 30.0

    # HIGH SIGNALS (+15-20)
    # =====================

    # 1. State-changing methods: +15
    if endpoint.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        score += 15

    # 2. Check for high-priority params: +20
    if endpoint.params:
        if any(p in HIGH_PRIORITY_PARAMS for p in endpoint.params):
            score += 20

    # 3. Check for high-priority paths: +15
    url_lower = endpoint.url.lower()
    if any(path in url_lower for path in HIGH_PRIORITY_PATHS):
        score += 15

    # 4. Param count bonus: min(param_count * 3, 15)
    param_count = len(endpoint.params) + len(endpoint.body_fields)
    if param_count > 0:
        score += min(param_count * 3, 15)

    # 5. Sensitive response headers: +5 each
    if endpoint.response_headers:
        for header_name in endpoint.response_headers.keys():
            if header_name.lower() in SENSITIVE_HEADERS:
                score += 5

    # LOW SIGNALS (-10 to -25)
    # =======================

    # 1. Static/CDN paths: -25
    if any(ext in url_lower for ext in STATIC_EXTENSIONS):
        score -= 25
    elif any(path in url_lower for path in STATIC_PATHS):
        score -= 25

    # 2. No params + GET: -10
    if endpoint.method == 'GET' and param_count == 0:
        score -= 10

    # Clamp score to 0-100 range
    return max(0.0, min(100.0, score))


def score_all_endpoints(endpoints: list) -> list:
    """Score all endpoints and return sorted by priority (descending).

    Args:
        endpoints: List of Endpoint instances

    Returns:
        List of endpoints sorted by priority_score (highest first)
    """
    for endpoint in endpoints:
        endpoint.priority_score = score_endpoint(endpoint)

    return sorted(endpoints, key=lambda e: e.priority_score, reverse=True)
