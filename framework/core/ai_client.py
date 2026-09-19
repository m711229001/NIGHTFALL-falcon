import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Dict, Optional
import httpx

try:
    from core.ai_config_store import get_ai_config
except ImportError:
    get_ai_config = None

logger = logging.getLogger("AIClient")


# =====================================================================
# 1. Base Interface
# =====================================================================
class BaseAIProvider(ABC):
    @abstractmethod
    async def build_request(
        self,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
    ) -> tuple[str, Dict[str, str], Dict[str, Any]]:
        pass

    @abstractmethod
    def parse_response(self, data: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    def parse_stream_chunk(self, line: str) -> Optional[str]:
        pass


# =====================================================================
# 2. Providers
# =====================================================================

class OpenAIProvider(BaseAIProvider):
    """OpenAI-compatible: OpenAI, DeepSeek, Groq, Together, OpenRouter, Ollama, Mistral."""

    async def build_request(
        self,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
    ) -> tuple[str, Dict[str, str], Dict[str, Any]]:
        # Build chat completions URL
        if base_url:
            base = base_url.rstrip("/")
            if base.endswith("/chat/completions"):
                url = base
            elif base.endswith("/v1"):
                url = base + "/chat/completions"
            else:
                url = base + "/v1/chat/completions"
        else:
            url = "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        return url, headers, payload

    def parse_response(self, data: Dict[str, Any]) -> str:
        return data["choices"][0]["message"]["content"]

    def parse_stream_chunk(self, line: str) -> Optional[str]:
        if line.startswith("data: ") and line != "data: [DONE]":
            import json
            try:
                data = json.loads(line[6:])
                return data["choices"][0]["delta"].get("content", "")
            except Exception:
                return None
        return None


class ClaudeProvider(BaseAIProvider):
    async def build_request(
        self,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
    ) -> tuple[str, Dict[str, str], Dict[str, Any]]:
        if base_url:
            base = base_url.rstrip("/")
            if base.endswith("/messages"):
                url = base
            elif base.endswith("/v1"):
                url = base + "/messages"
            else:
                url = base + "/v1/messages"
        else:
            url = "https://api.anthropic.com/v1/messages"

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        return url, headers, payload

    def parse_response(self, data: Dict[str, Any]) -> str:
        return data["content"][0]["text"]

    def parse_stream_chunk(self, line: str) -> Optional[str]:
        if line.startswith("data: "):
            import json
            try:
                data = json.loads(line[6:])
                if data.get("type") == "content_block_delta":
                    return data["delta"].get("text", "")
            except Exception:
                return None
        return None


class GeminiProvider(BaseAIProvider):
    async def build_request(
        self,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
    ) -> tuple[str, Dict[str, str], Dict[str, Any]]:
        if base_url:
            base = base_url.rstrip("/")
            if ":generateContent" in base:
                endpoint = base
            else:
                endpoint = base + f"/models/{model}:generateContent"
        else:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

        url = f"{endpoint}?key={api_key}"
        headers = {"Content-Type": "application/json"}

        contents = [{"role": "user", "parts": [{"text": user_prompt}]}]
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        return url, headers, payload

    def parse_response(self, data: Dict[str, Any]) -> str:
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def parse_stream_chunk(self, line: str) -> Optional[str]:
        import json
        try:
            data = json.loads(line)
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None


# =====================================================================
# 3. Universal Client
# =====================================================================

class UniversalAIClient:
    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries
        self._providers: Dict[str, BaseAIProvider] = {
            "openai": OpenAIProvider(),
            "deepseek": OpenAIProvider(),
            "groq": OpenAIProvider(),
            "mistral": OpenAIProvider(),
            "openrouter": OpenAIProvider(),
            "together": OpenAIProvider(),
            "ollama": OpenAIProvider(),
            "claude": ClaudeProvider(),
            "anthropic": ClaudeProvider(),
            "gemini": GeminiProvider(),
        }

    def register_provider(self, name: str, provider: BaseAIProvider):
        self._providers[name.lower()] = provider

    async def generate_from_active(
        self,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        timeout: Optional[float] = None,
        stream: bool = False,
    ):
        if not get_ai_config:
            raise RuntimeError("ai_config_store not available.")

        active = get_ai_config().get_active_provider()
        if not active or not active.get("api_key"):
            raise ValueError("No active provider with API key in ai_config_store.")

        provider_name = active["name"].lower()
        if timeout is None:
            timeout_map = {
                "openai": 90.0, "claude": 90.0, "anthropic": 90.0,
                "gemini": 45.0, "ollama": 120.0, "deepseek": 90.0,
            }
            timeout = timeout_map.get(provider_name, 60.0)

        if stream:
            return self.generate_stream(
                provider=provider_name,
                api_key=active["api_key"],
                model=active["model"],
                user_prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                base_url=active.get("base_url"),
                timeout=timeout,
            )

        return await self.generate_text(
            provider=provider_name,
            api_key=active["api_key"],
            model=active["model"],
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            base_url=active.get("base_url"),
            timeout=timeout,
        )

    async def generate_text(
        self,
        provider: str,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
    ) -> str:
        provider_key = provider.lower()
        if provider_key not in self._providers:
            raise ValueError(f"Provider '{provider}' not supported.")

        provider_impl = self._providers[provider_key]

        url, headers, payload = await provider_impl.build_request(
            api_key=api_key,
            model=model,
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            base_url=base_url,
        )

        last_exception = None

        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    logger.info(f"AI request to [{provider}] (attempt {attempt}/{self.max_retries})...")
                    response = await client.post(url, headers=headers, json=payload)

                    if response.status_code in [429, 500, 502, 503, 504]:
                        if attempt < self.max_retries:
                            wait_time = 2 ** attempt
                            logger.warning(f"Status {response.status_code}. Retry in {wait_time}s...")
                            await asyncio.sleep(wait_time)
                            continue

                    response.raise_for_status()
                    data = response.json()
                    return provider_impl.parse_response(data)

                except httpx.HTTPStatusError as e:
                    logger.error(f"HTTP error from {provider}: {e.response.status_code} - {e.response.text[:300]}")
                    raise RuntimeError(f"Provider error [{e.response.status_code}]: {e.response.text[:300]}")

                except httpx.RequestError as e:
                    last_exception = e
                    logger.warning(f"Network error attempt {attempt}: {str(e)}")
                    if attempt < self.max_retries:
                        await asyncio.sleep(2 ** attempt)

            raise RuntimeError(
                f"Failed to connect to [{provider}] after {self.max_retries} attempts. "
                f"Last error: {str(last_exception)}"
            )

    async def generate_stream(
        self,
        provider: str,
        api_key: str,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4000,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
    ) -> AsyncGenerator[str, None]:
        provider_key = provider.lower()
        if provider_key not in self._providers:
            raise ValueError(f"Provider '{provider}' not supported.")

        provider_impl = self._providers[provider_key]

        url, headers, payload = await provider_impl.build_request(
            api_key=api_key,
            model=model,
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            base_url=base_url,
        )

        if provider_key in ["openai", "deepseek", "groq", "mistral", "openrouter", "together", "ollama"]:
            payload["stream"] = True

        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        chunk = provider_impl.parse_stream_chunk(line)
                        if chunk:
                            yield chunk