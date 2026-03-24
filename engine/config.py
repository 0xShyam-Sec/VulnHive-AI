"""Centralized scan configuration."""
import os


class ScanConfig:
    """Configuration for scan execution."""

    def __init__(self, **kwargs):
        """Initialize ScanConfig with defaults and apply kwargs."""
        # Set defaults
        self.llm_backend = "ollama"
        self.ollama_url = "http://localhost:11434/api/chat"
        self.ollama_model = "deepseek-r1:14b"
        self.anthropic_model = "claude-haiku-4-5-20251001"
        self.anthropic_validator_model = "claude-sonnet-4-6"
        self.max_depth = 3
        self.max_requests_per_second = 20
        self.max_reactive_spawns = 10
        self.max_chain_depth = 3
        self.checkpoint_interval_sec = 300
        self.aggressive_mode = False
        self.excluded_paths = []
        self.cookies = {}
        self.auth_headers = {}
        self.bearer_token = ""

        # Apply kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def llm_available(self):
        """Check if LLM is available based on backend."""
        if self.llm_backend == "anthropic":
            return "ANTHROPIC_API_KEY" in os.environ
        return True

    def get_auth_headers(self):
        """Return auth headers with Bearer token if set."""
        headers = dict(self.auth_headers)
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers
