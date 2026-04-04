"""Playwright 版 Sentinel SDK token 获取辅助。

提供两种模式：
  1. 单 flow 模式 — get_sentinel_token_via_browser()：每次启动一个浏览器获取单个 flow 的 token
  2. 批量多 flow 模式 — get_sentinel_tokens_batch()：一次浏览器会话生成所有注册流程需要的 token

推荐使用批量模式，一次浏览器启动即可获取全部 token（~9s/flow），效率更高。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from core.browser_runtime import (
    ensure_browser_display_available,
    resolve_browser_headless,
)
from core.proxy_utils import build_playwright_proxy_config


DEFAULT_SDK_VERSION = "20260219f9f6"
DEFAULT_FRAME_URL = (
    f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={DEFAULT_SDK_VERSION}"
)
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.7103.92 Safari/537.36"
)

REGISTRATION_FLOWS = [
    "authorize_continue",
    "username_password_create",
    "password_verify",
    "oauth_create_account",
]

FLOW_NEEDS_SO_TOKEN = {"oauth_create_account"}


def _flow_page_url(flow: str) -> str:
    flow_name = str(flow or "").strip().lower()
    mapping = {
        "authorize_continue": "https://auth.openai.com/create-account",
        "username_password_create": "https://auth.openai.com/create-account/password",
        "password_verify": "https://auth.openai.com/log-in/password",
        "email_otp_validate": "https://auth.openai.com/email-verification",
        "oauth_create_account": "https://auth.openai.com/about-you",
    }
    return mapping.get(flow_name, "https://auth.openai.com/about-you")


@dataclass
class SentinelBatchTokens:
    """批量 sentinel token 结果容器。"""

    device_id: str = ""
    tokens: dict[str, str] = field(default_factory=dict)
    so_tokens: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def get_token(self, flow: str) -> Optional[str]:
        return self.tokens.get(flow)

    def get_so_token(self, flow: str) -> Optional[str]:
        return self.so_tokens.get(flow)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def success_flows(self) -> list[str]:
        return [f for f in self.tokens if f not in self.errors]


def _run_batch_in_browser(
    *,
    flows: list[str],
    proxy: Optional[str] = None,
    timeout_ms: int = 60000,
    headless: bool = True,
    device_id: Optional[str] = None,
    frame_url: Optional[str] = None,
    user_agent: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> SentinelBatchTokens:
    """
    在一个 Playwright 浏览器会话中批量生成多个 flow 的 sentinel token。

    核心思路（来自方案二 dc33acce4e57060b5cef5f847c2cc8a2e2bbb79f.txt）：
      打开 sentinel frame 页面 → SDK 自动加载 → 对每个 flow 调用
      SentinelSDK.init(flow) + SentinelSDK.token(flow) 获取完整 p/t/c token，
      对 oauth_create_account 额外调用 sessionObserverToken(flow)。
    """
    logger = log_fn or (lambda _msg: None)
    result = SentinelBatchTokens(device_id=device_id or "")
    t_start = time.time()

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        logger(f"Sentinel Batch Browser 不可用: {e}")
        for f in flows:
            result.errors[f] = f"playwright unavailable: {e}"
        return result

    effective_headless, reason = resolve_browser_headless(headless)
    ensure_browser_display_available(effective_headless)
    logger(
        f"Sentinel Batch Browser: {'headless' if effective_headless else 'headed'} ({reason})"
    )

    launch_args: dict[str, Any] = {
        "headless": effective_headless,
        "args": [
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
        ],
    }
    proxy_config = build_playwright_proxy_config(proxy)
    if proxy_config:
        launch_args["proxy"] = proxy_config

    target_frame_url = frame_url or DEFAULT_FRAME_URL
    effective_ua = user_agent or DEFAULT_USER_AGENT

    logger(f"Sentinel Batch Browser 启动: flows={flows}, frame={target_frame_url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_args)
        try:
            context = browser.new_context(
                user_agent=effective_ua,
                locale="en-US",
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )
            if device_id:
                try:
                    context.add_cookies(
                        [
                            {
                                "name": "oai-did",
                                "value": str(device_id),
                                "url": "https://sentinel.openai.com/",
                                "path": "/",
                                "secure": True,
                                "sameSite": "Lax",
                            },
                            {
                                "name": "oai-did",
                                "value": str(device_id),
                                "url": "https://auth.openai.com/",
                                "path": "/",
                                "secure": True,
                                "sameSite": "Lax",
                            },
                        ]
                    )
                except Exception:
                    pass

            page = context.new_page()
            page.goto(target_frame_url, wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(5000)

            try:
                page.wait_for_function(
                    "() => !!window.SentinelSDK",
                    timeout=min(timeout_ms, 30000),
                )
            except Exception:
                sdk_url = (
                    f"https://sentinel.openai.com/sentinel/{DEFAULT_SDK_VERSION}/sdk.js"
                )
                page.evaluate(
                    """
                    async (sdkUrl) => {
                        const existing = Array.from(document.scripts || [])
                            .some((item) => item.src === sdkUrl);
                        if (existing) return;
                        await new Promise((resolve, reject) => {
                            const script = document.createElement('script');
                            script.src = sdkUrl;
                            script.async = true;
                            script.onload = () => resolve(true);
                            script.onerror = () => reject(new Error('Failed to load ' + sdkUrl));
                            document.head.appendChild(script);
                        });
                    }
                    """,
                    sdk_url,
                )
                page.wait_for_function(
                    "() => !!window.SentinelSDK",
                    timeout=min(timeout_ms, 30000),
                )

            logger("SentinelSDK 已加载，开始生成各 flow token...")

            for flow in flows:
                flow_start = time.time()
                try:
                    raw = page.evaluate(
                        """
                        async ({ flow }) => {
                            if (!window.SentinelSDK) {
                                throw new Error('SentinelSDK missing');
                            }
                            if (typeof window.SentinelSDK.init === 'function') {
                                await window.SentinelSDK.init(flow);
                            }
                            const tok = await window.SentinelSDK.token(flow);
                            let soTok = null;
                            try {
                                soTok = await window.SentinelSDK.sessionObserverToken(flow);
                            } catch (e) {
                                soTok = null;
                            }
                            return { token: tok, soToken: soTok };
                        }
                        """,
                        {"flow": flow},
                    )

                    elapsed = time.time() - flow_start
                    token_str = (raw or {}).get("token") if isinstance(raw, dict) else None
                    so_token_str = (raw or {}).get("soToken") if isinstance(raw, dict) else None

                    if token_str:
                        result.tokens[flow] = str(token_str).strip()
                        if so_token_str and flow in FLOW_NEEDS_SO_TOKEN:
                            result.so_tokens[flow] = str(so_token_str).strip()

                        try:
                            parsed = json.loads(token_str)
                            has_p = bool(parsed.get("p"))
                            has_t = bool(parsed.get("t"))
                            has_c = bool(parsed.get("c"))
                            logger(
                                f"  [{flow}] ✓ ({elapsed:.1f}s) "
                                f"p={'✓' if has_p else '✗'} "
                                f"t={'✓' if has_t else '✗'} "
                                f"c={'✓' if has_c else '✗'}"
                                + (f" so={'✓' if so_token_str else '✗'}" if flow in FLOW_NEEDS_SO_TOKEN else "")
                            )
                        except Exception:
                            logger(f"  [{flow}] ✓ ({elapsed:.1f}s) len={len(str(token_str))}")
                    else:
                        result.errors[flow] = "empty token response"
                        logger(f"  [{flow}] ✗ ({elapsed:.1f}s): empty token")
                except Exception as e:
                    elapsed = time.time() - flow_start
                    result.errors[flow] = str(e)
                    logger(f"  [{flow}] ✗ ({elapsed:.1f}s): {e}")

        except Exception as e:
            logger(f"Sentinel Batch Browser 异常: {e}")
            for f in flows:
                if f not in result.tokens and f not in result.errors:
                    result.errors[f] = str(e)
        finally:
            browser.close()

    result.elapsed_seconds = time.time() - t_start
    ok_count = len(result.tokens)
    total = len(flows)
    logger(
        f"Sentinel Batch Browser 完成: {ok_count}/{total} 成功, "
        f"耗时 {result.elapsed_seconds:.1f}s"
    )
    return result


def get_sentinel_tokens_batch(
    *,
    flows: Optional[list[str]] = None,
    proxy: Optional[str] = None,
    timeout_ms: int = 60000,
    headless: bool = True,
    device_id: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> SentinelBatchTokens:
    """
    批量获取 sentinel token（一次浏览器会话完成所有 flow）。

    默认生成注册全流程所需的 4 个 flow token：
      authorize_continue, username_password_create, password_verify, oauth_create_account

    其中 oauth_create_account 额外包含 session observer token。

    Args:
        flows: 要生成的 flow 列表，默认为 REGISTRATION_FLOWS
        proxy: 代理地址
        timeout_ms: 单次超时（毫秒）
        headless: 是否无头模式
        device_id: 设备 ID（设置 oai-did cookie）
        log_fn: 日志回调函数

    Returns:
        SentinelBatchTokens: 包含所有 flow 的 token 结果
    """
    return _run_batch_in_browser(
        flows=flows or list(REGISTRATION_FLOWS),
        proxy=proxy,
        timeout_ms=timeout_ms,
        headless=headless,
        device_id=device_id,
        log_fn=log_fn,
    )


def get_sentinel_token_via_browser(
    *,
    flow: str,
    proxy: Optional[str] = None,
    timeout_ms: int = 45000,
    page_url: Optional[str] = None,
    headless: bool = True,
    device_id: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """通过浏览器直接调用 SentinelSDK.token(flow) 获取完整 token（单 flow 模式）。"""
    logger = log_fn or (lambda _msg: None)

    batch_result = get_sentinel_tokens_batch(
        flows=[flow],
        proxy=proxy,
        timeout_ms=timeout_ms,
        headless=headless,
        device_id=device_id,
        log_fn=log_fn,
    )

    token = batch_result.get_token(flow)
    if not token and batch_result.errors.get(flow):
        logger(
            "Sentinel Browser 获取失败: " + batch_result.errors.get(flow, "unknown")
        )
    return token
