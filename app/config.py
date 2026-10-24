import os


class Settings:
    aipipe_token = os.environ.get("AIPIPE_TOKEN", "")
    llm_base_url = os.environ.get("LLM_BASE_URL", "https://aipipe.org/openai/v1").rstrip("/")
    llm_model = os.environ.get("LLM_MODEL", "gpt-4.1-mini")
    llm_fallback_model = os.environ.get("LLM_FALLBACK_MODEL", "")
    llm_timeout_s = float(os.environ.get("LLM_TIMEOUT_S", "14"))
    data_dir = os.environ.get("DATA_DIR", "/tmp/incident-agent")
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_bodies = os.environ.get("LOG_BODIES", "0") == "1"
    debug_token = os.environ.get("DEBUG_TOKEN", "")
    max_body_bytes = 2_000_000
    request_budget_s = 16.0  # grader allows 18s per request


settings = Settings()
