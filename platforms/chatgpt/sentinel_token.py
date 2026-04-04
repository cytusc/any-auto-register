"""
Sentinel Token 生成器模块（纯 Python 方案 + HTTP API 获取 c 字段）。

注意：OpenAI Sentinel SDK 已升级到 20260219f9f6，新增 Turnstile VM 验证。
纯 Python 方式生成的 token 中 t 字段为空串，仅适用于不需要 Turnstile 的场景。
需要完整 p/t/c 三字段的场景请使用 sentinel_browser / sentinel_batch 的 Playwright 模式。
"""

import base64
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta


SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_REFERER = "https://sentinel.openai.com/backend-api/sentinel/frame.html"

SDK_VERSION = "20260219f9f6"
SDK_URL = f"https://sentinel.openai.com/sentinel/{SDK_VERSION}/sdk.js"


class SentinelTokenGenerator:
    """
    Sentinel Token 纯 Python 生成器（SDK 20260219f9f6 版本）。

    说明：
    - 该实现不依赖 Node / JS。
    - t 字段按当前纯 Python 方案固定空串（Turnstile VM 无法纯 HTTP 模拟）。
    - config 数组已更新为 25 元素（新版 SDK 要求）。
    """

    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/136.0.7103.92 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self):
        now = datetime.now()
        utc_offset = now.astimezone().utcoffset()
        offset_hours = int(utc_offset.total_seconds() // 3600) if utc_offset else 0
        offset_minutes = int((abs(utc_offset.total_seconds()) % 3600) // 60) if utc_offset else 0
        sign = "+" if offset_hours >= 0 else "-"
        tz_str = f"GMT{sign}{abs(offset_hours):02d}{offset_minutes:02d}"
        tz_names = {
            8: "中国标准时间",
            0: "Coordinated Universal Time",
            -5: "Eastern Standard Time",
            -8: "Pacific Standard Time",
        }
        tz_name = tz_names.get(offset_hours, "Coordinated Universal Time")
        date_str = now.strftime(f"%a %b %d %Y %H:%M:%S {tz_str} ({tz_name})")
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop_values = [
            "windowControlsOverlay\u2212[object WindowControlsOverlay]",
            "scheduling\u2212[object Scheduling]",
            "pdfViewerEnabled\u2212true",
            "hardwareConcurrency\u221216",
            "deviceMemory\u22128",
            "maxTouchPoints\u22120",
            "cookieEnabled\u2212true",
            "vendor\u2212Google Inc.",
            "language\u2212en-US",
            "onLine\u2212true",
            "webdriver\u2212false",
        ]
        return [
            random.choice([2560, 2667, 2745, 2880, 3000, 2200, 2160]),
            date_str,
            4294967296,
            random.random(),
            self.user_agent,
            SDK_URL,
            None,
            random.choice(["en-US", "zh-CN", "en"]),
            "en-US",
            "en-US,en",
            random.random(),
            random.choice(nav_prop_values),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice([
                "__oai_so_bm", "__oai_logHTML", "__NEXT_DATA__",
                "__next_f", "__oai_SSR_TTI", "__oai_SSR_HTML",
                "__reactEvents", "__RUNTIME_CONFIG__",
            ]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time_origin,
            0,
            0,
            0,
            0,
            0,
            0,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        encoded = self._base64_encode(config)
        digest = self._fnv1a_32(seed + encoded)
        if digest[: len(difficulty)] <= difficulty:
            return encoded + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed or self.requirements_seed
        difficulty = difficulty or "0"
        start_time = time.time()
        config = self._get_config()
        for nonce in range(self.MAX_ATTEMPTS):
            value = self._run_check(start_time, seed, difficulty, config, nonce)
            if value:
                return "gAAAAAB" + value
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)


def fetch_sentinel_challenge(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
    request_p=None,
):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": str(request_p or "").strip() or generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or generator.user_agent,
        "sec-ch-ua": sec_ch_ua
        or '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate
    try:
        response = session.post(SENTINEL_REQ_URL, **kwargs)
        if response.status_code == 200:
            return response.json()
    except Exception:
        return None
    return None


def _build_sentinel_token_python(
    session,
    device_id,
    *,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
):
    challenge = fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )
    if not challenge:
        return None

    c_value = str(challenge.get("token") or "").strip()
    if not c_value:
        return None

    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    pow_data = challenge.get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    return json.dumps(
        {
            "p": p_value,
            "t": "",
            "c": c_value,
            "id": device_id,
            "flow": flow,
        },
        separators=(",", ":"),
    )


def build_sentinel_token(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
):
    """默认 Sentinel token 构造：纯 Python。"""
    return _build_sentinel_token_python(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )


def build_sentinel_token_vm_only(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
):
    """
    VM 分支专用构造器（命名保持不变，内部使用纯 Python）。
    """
    return _build_sentinel_token_python(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )

