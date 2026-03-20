# Task 4.1 Verification - Exploitation Engine Context Analyzer

## Files Created

### 1. `/Users/shyamk/Documents/pentest-agent/exploit/__init__.py`
- Module docstring: "Exploitation engine — context analysis, filter detection, payload library."

### 2. `/Users/shyamk/Documents/pentest-agent/exploit/context_analyzer.py`
Complete implementation with:

#### CONTEXTS Dictionary (11 context types)
- `html_body`: Reflected in HTML body (unquoted, outside tags)
- `html_attribute_double`: Inside HTML attribute with double quotes
- `html_attribute_single`: Inside HTML attribute with single quotes
- `html_attribute_unquoted`: Inside unquoted HTML attribute
- `javascript_string_double`: Inside JavaScript string with double quotes
- `javascript_string_single`: Inside JavaScript string with single quotes
- `javascript_template`: Inside JavaScript template literal (backticks)
- `json_value`: Inside JSON string value
- `url_param`: Inside URL parameter (href, src, action, etc)
- `http_header`: Reflected in HTTP response header
- `not_reflected`: Input not reflected in response

#### ReflectionResult Dataclass
- `reflected: bool` - Whether input was reflected
- `contexts: List[str]` - List of detected context types
- `raw_positions: List[Tuple[int, str]]` - (position, surrounding_chars) tuples
- `canary: str` - The injected canary string
- `response_status: int` - HTTP response status code
- `response_length: int` - Response body length

#### _classify_context() Function
Analyzes 200 chars before canary to determine context:
- Detects `<script>` blocks and counts quote types (backtick, double, single)
- Detects HTML tags and attribute quote types
- Detects JSON context (preceding `:` and `"`)
- Detects URL parameter attributes (href, src, action, redirect, location)
- Defaults to html_body

#### analyze_reflection() Function
Parameters:
- `url: str` - Target URL
- `param: str` - Parameter name to inject into
- `method: str = "GET"` - HTTP method
- `config: Optional[object] = None` - ScanConfig for auth/cookies
- `timeout: int = 10` - Request timeout
- `verify_ssl: bool = False` - SSL verification flag

Implementation:
1. Generates canary: `f"xPENx{uuid.uuid4().hex[:8]}xTESTx"`
2. For GET: Adds canary as query parameter
3. For POST: Adds canary as form data parameter
4. Respects config auth headers and cookies if provided
5. Makes HTTP request with httpx.Client
6. Checks both response headers and body for canary
7. For each occurrence, calls _classify_context() to determine type
8. Returns ReflectionResult with all findings

## Implementation Details

### Canary Generation
- Format: `xPENx{8-char-uuid}xTESTx`
- Ensures uniqueness and detectability
- Example: `xPENx1a2b3c4dxTESTx`

### Context Detection Logic
- **JavaScript**: Detects `<script>` tags, counts unescaped quotes to determine string type
- **HTML Attributes**: Detects `<tag` context, checks for `="` or `='` patterns
- **JSON**: Looks for `":` or `": ` patterns in prefix
- **URL Parameters**: Matches href, src, action, redirect, location attributes
- **HTML Body**: Default fallback for untagged context

### HTTP Request Handling
- Uses httpx.Client with configurable timeout and SSL verification
- Supports GET (query params) and POST (form data)
- Follows redirects by default
- Integrates with engine.config for authentication
- Graceful error handling returns empty reflection result

## Verification Checklist

✓ File 1 created: `/Users/shyamk/Documents/pentest-agent/exploit/__init__.py`
✓ File 2 created: `/Users/shyamk/Documents/pentest-agent/exploit/context_analyzer.py`
✓ CONTEXTS dict with 11 context types
✓ ReflectionResult dataclass with all 6 required fields
✓ _classify_context() function with all context detection logic
✓ analyze_reflection() function with full implementation
✓ Canary format matches spec: `xPENx{uuid.hex[:8]}xTESTx`
✓ GET parameter handling with URL parsing
✓ POST data handling
✓ Response body scanning for canary
✓ Response header scanning for canary
✓ Config integration for auth/cookies
✓ Exception handling for network errors
✓ All imports present (uuid, httpx, urllib.parse, re)

## Ready for Commit

```bash
git add exploit/ && git commit -m "feat: add context analyzer — canary injection + reflection context detection"
```

## Test Command

```bash
python3 -c "
from exploit.context_analyzer import analyze_reflection, CONTEXTS
print(f'{len(CONTEXTS)} context types defined')
result = analyze_reflection('https://httpbin.org/get', 'test', 'GET')
print(f'Reflected: {result.reflected}, Contexts: {result.contexts}, Status: {result.response_status}')
print('Context analyzer OK')
"
```
