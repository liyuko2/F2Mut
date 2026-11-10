#!/usr/bin/env python3
"""Shared LLM configuration resolution helpers."""

import os


COMMON_MODEL_ENV = "AFL_LLM_MODEL"
COMMON_BASE_URL_ENV = "AFL_LLM_BASE_URL"
COMMON_API_KEY_ENV = "AFL_LLM_API_KEY"
COMMON_API_KEY_NAME_ENV = "AFL_LLM_API_KEY_ENV"
LEGACY_MODEL_ENV = "MODULE_NAME"
LEGACY_BASE_URL_ENV = "MODULE_URL"
LEGACY_PROVIDER_ENV = "MODULE"

DEFAULT_GLM_MODEL = "glm-4-flash-250414"
DEFAULT_SHARED_MODEL = "deepseek-v4-flash"
DEFAULT_OPENAI_COMPAT_BASE_URL = "https://api.deepseek.com"


def _first_env_value(names):
    for name in names or ():
        value = os.environ.get(str(name))
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _named_env_value(pointer_name):
    pointer = os.environ.get(str(pointer_name))
    if not isinstance(pointer, str) or not pointer.strip():
        return None
    value = os.environ.get(pointer.strip())
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def is_glm_model(model):
    return str(model or "").strip().lower().startswith("glm-")


def is_deepseek_model(model):
    return str(model or "").strip().lower().startswith("deepseek")


def default_model_name(default=None):
    configured = _first_env_value((COMMON_MODEL_ENV, LEGACY_MODEL_ENV))
    if configured:
        return normalize_model_name(configured, default=default)
    if str(os.environ.get(LEGACY_PROVIDER_ENV) or "").strip().upper() == "GLM":
        return DEFAULT_GLM_MODEL
    return str(default or DEFAULT_SHARED_MODEL).strip()


def normalize_model_name(model, default=None):
    model = str(model or "").strip()
    if model.upper() == "GLM":
        return DEFAULT_GLM_MODEL
    if model:
        return model
    return default_model_name(default=default)


def resolve_model(explicit_model=None, legacy_env_names=(), default=None):
    if isinstance(explicit_model, str) and explicit_model.strip():
        return normalize_model_name(explicit_model, default=default)
    configured = _first_env_value((COMMON_MODEL_ENV,))
    if configured:
        return normalize_model_name(configured, default=default)
    configured = _first_env_value(tuple(legacy_env_names or ()))
    if configured:
        return normalize_model_name(configured, default=default)
    configured = _first_env_value((LEGACY_MODEL_ENV,))
    if configured:
        return normalize_model_name(configured, default=default)
    return normalize_model_name(None, default=default)


def resolve_api_key(model, explicit_key=None, explicit_key_env=None, legacy_pointer_env_names=()):
    if isinstance(explicit_key, str) and explicit_key.strip():
        return explicit_key.strip()
    if isinstance(explicit_key_env, str) and explicit_key_env.strip():
        value = os.environ.get(explicit_key_env.strip())
        if isinstance(value, str) and value.strip():
            return value.strip()
    configured = _first_env_value((COMMON_API_KEY_ENV,))
    if configured:
        return configured
    configured = _named_env_value(COMMON_API_KEY_NAME_ENV)
    if configured:
        return configured
    for name in tuple(legacy_pointer_env_names or ()):
        configured = _named_env_value(name)
        if configured:
            return configured
    if is_glm_model(model):
        return _first_env_value(("ZHIPU_API_KEY", "GLM_API_KEY", "OPENAI_API_KEY"))
    if is_deepseek_model(model):
        return _first_env_value(("DEEPSEEK_API_KEY", "OPENAI_API_KEY"))
    return _first_env_value(("OPENAI_API_KEY",))


def resolve_base_url(model, explicit_url=None, legacy_env_names=(), default_openai_compat_base_url=None):
    if is_glm_model(model):
        return None
    if isinstance(explicit_url, str) and explicit_url.strip():
        return explicit_url.strip()
    configured = _first_env_value((COMMON_BASE_URL_ENV,))
    if configured:
        return configured
    configured = _first_env_value(tuple(legacy_env_names or ()))
    if configured:
        return configured
    configured = _first_env_value((LEGACY_BASE_URL_ENV,))
    if configured:
        return configured
    if is_deepseek_model(model):
        return str(default_openai_compat_base_url or DEFAULT_OPENAI_COMPAT_BASE_URL).strip()
    return None
