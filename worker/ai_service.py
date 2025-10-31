import os
import time
import hashlib
from typing import Dict, Any, Tuple
import threading

try:
	from openai import OpenAI  # New SDK style
	experimental_openai = True
except Exception:
	experimental_openai = False
	import openai  # Fallback


class SimpleRateLimiter:
	"""Token bucket style limiter for local use."""
	def __init__(self, rate_per_minute: int = 30):
		self.capacity = rate_per_minute
		self.tokens = rate_per_minute
		self.timestamp = time.time()
		self.lock = threading.Lock()

	def allow(self) -> bool:
		with self.lock:
			now = time.time()
			# Refill
			elapsed = now - self.timestamp
			refill = int(elapsed * (self.capacity / 60.0))
			if refill > 0:
				self.tokens = min(self.capacity, self.tokens + refill)
				self.timestamp = now
			if self.tokens > 0:
				self.tokens -= 1
				return True
			return False


class SimpleCache:
	"""In-memory cache with TTL."""
	def __init__(self, ttl_seconds: int = 600):
		self.ttl = ttl_seconds
		self.store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
		self.lock = threading.Lock()

	def get(self, key: str):
		with self.lock:
			item = self.store.get(key)
			if not item:
				return None
				ts, value = item
			if time.time() - ts > self.ttl:
				self.store.pop(key, None)
				return None
			return value

	def set(self, key: str, value: Dict[str, Any]):
		with self.lock:
			self.store[key] = (time.time(), value)


def _hash_prompt(content: str) -> str:
	return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AIService:
	"""Provider-agnostic AI service wrapper (OpenAI-compatible)."""
	def __init__(self):
		self.api_key = os.getenv("OPENAI_API_KEY", "")
		self.model = os.getenv("LLM_MODEL", "gpt-3.5-turbo")
		self.enabled = bool(self.api_key) and os.getenv("ENABLE_AI_ANALYSIS", "true").lower() == "true"
		self.rate_limiter = SimpleRateLimiter(rate_per_minute=int(os.getenv("AI_RPM", "30")))
		self.cache = SimpleCache(ttl_seconds=int(os.getenv("AI_CACHE_TTL", "600")))
		self.provider = os.getenv("AI_PROVIDER", "openai").lower()

		if experimental_openai and self.provider == "openai":
			self.client = OpenAI(api_key=self.api_key)
		else:
			openai.api_key = self.api_key
			self.client = None

	def analyze(self, finding: Dict[str, Any]) -> Dict[str, Any]:
		if not self.enabled:
			return {"ai_summary": None, "ai_recommendation": None, "probable_fp": False}

		prompt = self._build_prompt(finding)
		cache_key = _hash_prompt(prompt)
		cached = self.cache.get(cache_key)
		if cached:
			return cached

		if not self.rate_limiter.allow():
			return {"ai_summary": None, "ai_recommendation": None, "probable_fp": False}

		response_text = self._call_model(prompt)
		parsed = self._parse_response(response_text)
		self.cache.set(cache_key, parsed)
		return parsed

	def _build_prompt(self, f: Dict[str, Any]) -> str:
		return (
			"Analyze this security finding and respond with three lines only:\n"
			"SUMMARY: <2-3 sentences>\n"
			"RECOMMENDATION: <2-3 sentences actionable>\n"
			"FALSE_POSITIVE: <YES|NO>\n\n"
			f"Tool: {f.get('tool')}\n"
			f"Title: {f.get('title')}\n"
			f"Severity: {f.get('severity')}\n"
			f"Endpoint: {f.get('endpoint')}\n"
			f"Description: {f.get('description')}\n"
		)

	def _call_model(self, prompt: str) -> str:
		if experimental_openai and self.client:
			res = self.client.chat.completions.create(
				model=self.model,
				messages=[{"role": "system", "content": "You are a security expert."}, {"role": "user", "content": prompt}],
				max_tokens=int(os.getenv("LLM_MAX_TOKENS", "400")),
				temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
			)
			return res.choices[0].message.content or ""
		else:
			res = openai.ChatCompletion.create(
				model=self.model,
				messages=[{"role": "system", "content": "You are a security expert."}, {"role": "user", "content": prompt}],
				max_tokens=int(os.getenv("LLM_MAX_TOKENS", "400")),
				temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
			)
			return res.choices[0].message["content"]

	def _parse_response(self, text: str) -> Dict[str, Any]:
		result = {"ai_summary": None, "ai_recommendation": None, "probable_fp": False}
		for line in (text or "").splitlines():
			if line.startswith("SUMMARY:"):
				result["ai_summary"] = line.replace("SUMMARY:", "").strip()
			elif line.startswith("RECOMMENDATION:"):
				result["ai_recommendation"] = line.replace("RECOMMENDATION:", "").strip()
			elif line.startswith("FALSE_POSITIVE:"):
				v = line.replace("FALSE_POSITIVE:", "").strip().upper()
				result["probable_fp"] = (v == "YES")
		return result
