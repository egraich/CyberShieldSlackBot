import os
import re
import asyncio
import base64
import aiohttp
from groq import AsyncGroq
from config import Config

class SecurityService:
    def __init__(self):
        self.groq_client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))
        self.vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.session = aiohttp.ClientSession()
        self.url_pattern = re.compile(
            r'(?:https?://)?'
            r'(?:[a-zA-Z0-9\-]+\.)+'
            r'[a-zA-Z]{2,24}'
            r'(?:/[^\s>|]*[^\s>|.,?!])?'
        )

    async def close(self):
        await self.session.close()

    def parse_risk_score(self, text: str):
            
        first_line = text.splitlines()[0]
    
        match = re.search(r"(\d{1,3})%", first_line)
        
        if match:
            val = int(match.group(1))
            return val if 0 <= val <= 100 else None
        return None
    
    def extract_url(self, text: str) -> str | None:
        match = self.url_pattern.search(text)
        if not match:
            return None
            
        url = match.group(0)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _encode_url_for_vt(self, url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode()).decode()
        return encoded.strip("=")

    async def _fetch_vt_data(self, url_id: str) -> tuple[int, dict | None]:
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-api-key": self.vt_api_key}

        async with self.session.get(api_url, headers=headers, timeout=10) as response:
            if response.status == 200:
                return response.status, await response.json()
            return response.status, None

    async def scan_url_virustotal(self, url: str) -> dict:
        if not self.vt_api_key:
            return {"status": "no_key"}

        try:
            url_id = self._encode_url_for_vt(url)
            status, json_data = await self._fetch_vt_data(url_id)
            
            if status == 200 and json_data:
                stats = json_data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values())
                }
            elif status == 404:
                return {"status": "not_found"}
            elif status == 401:
                return {"status": "auth_error"}
            elif status == 429:
                return {"status": "rate_limit"}
            else:
                return {"status": "error", "code": status}
                        
        except aiohttp.ClientTransientError:
            return {"status": "connection_error"}
        except Exception as e:
            return {"status": "unexpected_error", "error": str(e)}

    async def get_ai_verdict(self, text: str, vt_context: str = "") -> str:
        try:
            system_prompt = Config.BASE_RULES
            if vt_context:
                system_prompt += vt_context

            response = await self.groq_client.chat.completions.create(
                model=Config.GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text}
                ],
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return Config.AI_ERROR.format(error=str(e))

    async def scan_link_deep(self, url: str) -> dict:
        if not self.vt_api_key:
            return {"status": "no_key"}
            
        headers = {"x-apikey": self.vt_api_key}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        async with self.session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {"status": "success", "malicious": stats["malicious"], "total": sum(stats.values())}
            elif resp.status == 404:
                return await self._submit_and_poll(url, headers)
            elif resp.status == 401:
                return {"status": "error", "code": 401}
            else:
                return {"status": "error", "code": resp.status}

    async def _submit_and_poll(self, url: str, headers: dict) -> dict:
        payload = {"url": url}
        async with self.session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload) as resp:
            if resp.status != 200:
                return {"status": "error", "code": resp.status}
            data = await resp.json()
            analysis_id = data["data"]["id"]

        for _ in range(20):
            await asyncio.sleep(3)
            async with self.session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json()
                if data["data"]["attributes"]["status"] == "completed":
                    stats = data["data"]["attributes"]["stats"]
                    return {"status": "success", "malicious": stats["malicious"], "total": sum(stats.values())}
        
        return {"status": "timeout"}