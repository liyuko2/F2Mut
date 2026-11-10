import os
from contextlib import contextmanager

from openai import OpenAI

try:
    import httpx
except ImportError:
    httpx = None


def _load_api_key():
    env_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if env_key:
        return env_key
    try:
        with open("openai_key.txt", "r", encoding="utf-8") as file:
            return file.read().strip()
    except OSError:
        return ""


@contextmanager
def _temporary_env_unset(names):
    saved = {}
    for name in names:
        if name in os.environ:
            saved[name] = os.environ.pop(name)
    try:
        yield
    finally:
        for name, value in saved.items():
            os.environ[name] = value


OPENAI_KEY = _load_api_key()


def _create_client():
    kwargs = {
        "api_key": OPENAI_KEY,
    }
    base_url = (
        os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("AFL_LLM_BASE_URL")
        or ""
    ).strip()
    if base_url:
        kwargs["base_url"] = base_url

    all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    http_proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if all_proxy.lower().startswith("socks://"):
        if http_proxy and httpx is not None:
            kwargs["http_client"] = httpx.Client(proxy=http_proxy)
            return OpenAI(**kwargs)
        with _temporary_env_unset(("ALL_PROXY", "all_proxy")):
            return OpenAI(**kwargs)
    return OpenAI(**kwargs)


def llm(model, prompt, temperature):
    client = _create_client()

    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user", 
                "content": prompt
            }
        ],
        temperature=temperature
    )

    return response.choices[0].message.content

def llm_messages(model, messages, temperature):
    client = _create_client()
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    prompt = """
    hi
    """
    print(llm("gpt-4o-mini-2024-07-18", prompt))
