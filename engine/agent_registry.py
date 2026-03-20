"""
Agent Registry — registers all vulnerability agents with the DecisionEngine.

Maps vuln_type keys to agent test_endpoint functions. Handles:
1. Single-to-agent mapping (e.g., sqli → SQLiAgent)
2. Many-to-one mapping for compound types (e.g., graphql_* variants → GraphQLAgent)
3. Safe imports with try/except ImportError fallback
4. Instance reuse (single instance per agent class)
"""

from engine.decision_engine import DecisionEngine
from engine.config import ScanConfig


def register_all_agents(engine: DecisionEngine, config: ScanConfig) -> list:
    """
    Register all 13 existing vulnerability agents with DecisionEngine.

    Args:
        engine: DecisionEngine instance to register agents with
        config: ScanConfig with llm_backend for agent initialization

    Returns:
        List of (vuln_type, agent_class, success) tuples for verification
    """
    # Map: vuln_type → agent class
    agent_classes = {}
    # Map: agent class → instance (reuse same instance for same class)
    instances = {}

    # Define all agent registrations
    registrations = [
        ("sqli", "agents.vuln.sqli", "SQLiAgent"),
        ("xss", "agents.vuln.xss", "XSSAgent"),
        ("cmdi", "agents.vuln.cmdi", "CMDIAgent"),
        ("command_injection", "agents.vuln.cmdi", "CMDIAgent"),
        ("path_traversal", "agents.vuln.path_traversal", "PathTraversalAgent"),
        ("csrf", "agents.vuln.csrf", "CSRFAgent"),
        ("idor", "agents.vuln.idor", "IDORAgent"),
        ("ssrf", "agents.vuln.ssrf", "SSRFAgent"),
        ("open_redirect", "agents.vuln.open_redirect", "OpenRedirectAgent"),
        ("security_headers", "agents.vuln.headers", "HeadersAgent"),
        ("sensitive_data", "agents.vuln.sensitive_data", "SensitiveDataAgent"),
        ("graphql", "agents.vuln.graphql", "GraphQLAgent"),
        ("graphql_introspection", "agents.vuln.graphql", "GraphQLAgent"),
        ("graphql_depth", "agents.vuln.graphql", "GraphQLAgent"),
        ("graphql_batch", "agents.vuln.graphql", "GraphQLAgent"),
        ("graphql_injection", "agents.vuln.graphql", "GraphQLAgent"),
        ("mass_assignment", "agents.vuln.mass_assignment", "MassAssignmentAgent"),
        ("idor_advanced", "agents.vuln.idor_advanced", "IDORAdvancedAgent"),
        ("idor_mass_enum", "agents.vuln.idor_advanced", "IDORAdvancedAgent"),
        ("idor_write", "agents.vuln.idor_advanced", "IDORAdvancedAgent"),
        ("idor_delete", "agents.vuln.idor_advanced", "IDORAdvancedAgent"),
    ]

    registered = []

    for vuln_type, module_name, class_name in registrations:
        try:
            # Lazy import agent module
            module = __import__(module_name, fromlist=[class_name])
            agent_class = getattr(module, class_name)

            # Reuse instance if already created for this class
            if agent_class not in instances:
                instances[agent_class] = agent_class(llm_backend=config.llm_backend)

            agent_instance = instances[agent_class]

            # Register agent.test_endpoint with engine for this vuln_type
            engine.register_agent(vuln_type, agent_instance.test_endpoint)

            agent_classes[vuln_type] = agent_class
            registered.append((vuln_type, class_name, True))

        except ImportError as e:
            registered.append((vuln_type, class_name, False))
        except AttributeError as e:
            registered.append((vuln_type, class_name, False))
        except Exception as e:
            registered.append((vuln_type, class_name, False))

    return registered
