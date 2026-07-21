"""
visual_similarity.py — perceptual-hash brand impersonation detection.

Renders a candidate URL headlessly, computes a perceptual hash (pHash)
of the page, and compares it against a small reference set of known
brand login pages. A close visual match on a domain that is NOT the
real brand's registrable domain is a strong impersonation signal —
independent of and complementary to the structural features in
features.py.

── SECURITY NOTE — READ BEFORE DEPLOYING ────────────────────────────
This module fetches and renders attacker-controlled URLs. That is an
SSRF surface. The checks in this file (DNS pre-flight resolution,
per-hop redirect validation, JS disabled, no downloads/popups, hard
timeout) are the CODE-LEVEL mitigations and are necessary but NOT
sufficient on their own — they do not fully close DNS-rebinding
attacks (where a hostname resolves safely at check-time but to a
private IP by connect-time). The network-level mitigation (running
this in a container with firewall rules blocking egress to RFC1918 /
loopback / link-local ranges, e.g. via iptables or Docker network
policy) is a separate, mandatory piece of the puzzle before this ever
touches production traffic on a real server. Treat this module as
"safe for local development against a curated test set", not as
"safe to point at arbitrary live phishing URLs from prod" until that
network layer exists.
────────────────────────────────────────────────────────────────────

Usage:
    python3 visual_similarity.py https://paypal-verify.login.ru/secure

Standalone module — test this on its own (like whois_lookup.py) before
wiring it into predict.py / signals.py.
"""

import asyncio
import ipaddress
import os
import socket
import sys
from dataclasses import dataclass
from io import BytesIO
from urllib.parse import urlparse

import imagehash
from PIL import Image

# If Playwright's own browser download is unreachable (e.g. the CDN
# geo-blocks your region), set this to a system-installed Chromium/
# Chrome binary instead, e.g.:
#   export PLAYWRIGHT_CHROMIUM_EXECUTABLE=/usr/bin/chromium
CHROMIUM_EXECUTABLE = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")

# ── constants ─────────────────────────────────────────────────────────

NAVIGATION_TIMEOUT_MS = 8000
VIEWPORT = {"width": 1280, "height": 800}

# Below this Hamming distance, two pHashes are considered a visual match.
# pHash distances are typically 0 (identical) to 64 (totally different)
# for the default 8x8 hash. 10 is a reasonably conservative starting
# point — tune against real data before trusting it in production.
MATCH_THRESHOLD = 10

BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",  # CGNAT range too
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


class UnsafeTargetError(Exception):
    """Raised when a hostname (original or a redirect hop) resolves to
    a private/reserved address. Fail closed — never render."""


class RenderTimeoutError(Exception):
    """Raised when the page doesn't finish loading within the hard
    timeout. Distinct from UnsafeTargetError so callers can tell
    'blocked for safety' apart from 'target was just slow'."""


class RenderFailedError(Exception):
    """Any other render failure (bad TLS, connection refused, crash,
    unsupported scheme, etc). Callers must treat this the same as
    'visual check unavailable' — NOT as 'no visual match found'. A
    render failure is not evidence of legitimacy."""


# ── DNS pre-flight check ──────────────────────────────────────────────

def is_safe_target(hostname: str) -> bool:
    """
    Resolves hostname and rejects it if ANY returned address falls in
    a private/reserved range. This is a cheap early filter, not a
    complete defense — see the module docstring re: DNS rebinding.
    The real defense against rebinding is network-level egress
    filtering in the container this eventually runs in.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    if not infos:
        return False

    for *_rest, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if any(ip in net for net in BLOCKED_NETWORKS):
            return False

    return True


def _hostname_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


# ── result shape ───────────────────────────────────────────────────────

@dataclass
class VisualCheckResult:
    checked: bool                  # False if the check couldn't run at all
    phash: str = None              # hex string of the computed hash, if checked
    best_match_brand: str = None   # name of closest reference brand, if any
    best_match_distance: int = None
    is_match: bool = False         # True if best_match_distance <= MATCH_THRESHOLD
    unavailable_reason: str = None # set when checked is False — surface this,
                                    # never silently treat as "no match"
    screenshot_png: bytes = None   # raw PNG bytes, only populated if the
                                    # caller opted in via include_screenshot=True.
                                    # Safe to display directly (<img> tag /
                                    # base64 data URI) — it's a static image,
                                    # not executable content.


# ── screenshot + hash ──────────────────────────────────────────────────

async def _screenshot_bytes(url: str, settle_ms: int = 0, allow_javascript: bool = False) -> bytes:
    """
    Renders `url` and returns a PNG screenshot as bytes.

    settle_ms: extra time to wait AFTER domcontentloaded, BEFORE taking the
    screenshot. Defaults to 0 — a no-op, so the live candidate-URL check
    path (called with no args from check_visual_similarity) behaves exactly
    as before. Only the offline reference-capture flow should ever pass a
    nonzero value here: the per-request DNS guard below roughly doubles
    page-load latency (every resource, not just the main document, does a
    blocking-DNS-then-continue round trip), so on a resource-heavy real
    login page, domcontentloaded can fire before decorative images/fonts/
    background CSS have actually finished painting — the DOM is "loaded"
    but the page still looks visually incomplete in the screenshot. A
    fixed settle delay (2-3s is usually enough) gives those trailing
    requests time to land. Deliberately NOT applied by default: for the
    live SSRF-exposed path, an attacker-controlled page could keep
    "trailing requests" coming forever, and a wait here would just be
    extra attacker-controlled latency for no benefit against arbitrary
    URLs — only worth paying for a curated, one-time, manually-reviewed
    capture.

    allow_javascript: DANGEROUS outside the reference-capture flow — see
    the module's SECURITY NOTE. Defaults to False, which is what every
    live candidate-URL check must keep using: JS disabled removes a huge
    exploit surface against attacker-controlled pages. This flag exists
    ONLY because many real login pages (SPA-style banks/fintechs) render
    nothing but a blank page or a "please enable JavaScript" notice
    without it, which makes them useless as reference screenshots. It is
    safe to enable ONLY when: (1) the URL is a known-good, curated brand
    domain picked by a human, never attacker/user-supplied input, and
    (2) the resulting screenshot is manually reviewed before being hashed
    — exactly the reference-capture workflow this module documents.
    check_visual_similarity() (the live entry point predict.py/app.py
    call) also exposes this parameter, but callers on the live path must
    never set it to True.

    Safety measures applied here (code-level only — see module docstring):
      - initial hostname checked via is_safe_target() before navigation
      - EVERY subsequent request (including redirects) is intercepted
        and re-checked; anything resolving to a blocked range is aborted
      - JavaScript disabled by default — most phishing login pages render
        fine without it, and it removes a large exploit surface (see
        allow_javascript above for the narrow, opt-in exception)
      - downloads and popups blocked
      - hard navigation timeout
    """
    from playwright.async_api import async_playwright

    hostname = _hostname_of(url)
    if not hostname or not is_safe_target(hostname):
        raise UnsafeTargetError(f"blocked: {hostname!r} resolves to a disallowed range")

    async with async_playwright() as pw:
        launch_kwargs = dict(
            args=[
                "--no-sandbox", "--disable-gpu",
                # --no-sandbox only safe because the OUTER container is
                # what's actually sandboxing this process.
                #
                # --no-proxy-server as an explicit CLI flag, not just
                # Playwright's proxy=direct:// config: on some Chromium
                # builds, a system-level proxy setting (GNOME's
                # org.gnome.system.proxy, common on Kali boxes set up
                # for Burp Suite interception) overrides Playwright's
                # config-level proxy setting. The CLI flag wins
                # regardless of desktop integration.
                "--no-proxy-server",
            ],
            proxy={"server": "direct://"},
        )
        if CHROMIUM_EXECUTABLE:
            launch_kwargs["executable_path"] = CHROMIUM_EXECUTABLE

        browser = await pw.chromium.launch(**launch_kwargs)
        context = await browser.new_context(
            viewport=VIEWPORT,
            java_script_enabled=allow_javascript,
            accept_downloads=False,
            ignore_https_errors=True,  # phishing sites often have broken
                                        # certs; that's itself a signal
                                        # handled elsewhere, not a reason
                                        # to fail the render
        )
        page = await context.new_page()
        page.on("popup", lambda p: asyncio.ensure_future(p.close()))

        async def _guard_request(route):
            req_hostname = _hostname_of(route.request.url)
            scheme = urlparse(route.request.url).scheme
            if scheme not in ("http", "https"):
                await route.abort()
                return
            # is_safe_target() does blocking DNS resolution — run it off
            # the event loop so it doesn't serialize against every
            # resource a page loads (fonts, scripts, images...). On a
            # JS/asset-heavy page, doing this synchronously per-request
            # was enough added latency by itself to blow the navigation
            # timeout — see the github.com timeout case.
            loop = asyncio.get_running_loop()
            safe = await loop.run_in_executor(None, is_safe_target, req_hostname) if req_hostname else False
            if not safe:
                await route.abort()
                return
            await route.continue_()

        await page.route("**/*", _guard_request)

        try:
            # domcontentloaded rather than the default "load": we only
            # need the page rendered enough to screenshot, not every
            # image/font/analytics beacon to finish — those add latency
            # without changing what the phishing page visually looks
            # like, and JS is already disabled above.
            await page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")
        except Exception as e:
            await browser.close()
            if "Timeout" in type(e).__name__ or "timeout" in str(e).lower():
                raise RenderTimeoutError(str(e)) from e
            raise RenderFailedError(str(e)) from e

        if settle_ms:
            await page.wait_for_timeout(settle_ms)

        try:
            screenshot = await page.screenshot(type="png")
        finally:
            await browser.close()

        return screenshot


def compute_phash(image_bytes: bytes) -> imagehash.ImageHash:
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    return imagehash.phash(img)


# ── reference set ─────────────────────────────────────────────────────
# Populate by running build_reference_hash() once per brand against a
# known-good, manually verified screenshot (NOT a live fetch of the real
# site at check-time — pin a local reference image so a compromised real
# site can't poison your reference set).
#
# Populated 2026-07-21/22 against Iranian fintech/payment-gateway login
# pages (current focus — see reference_screenshots/ for the saved source
# images each hash below was built from; re-run build_reference_hash()
# against those if a hash ever needs to be regenerated, rather than
# re-fetching the live site). Each was rendered via
# `check_visual_similarity(url, include_screenshot=True)`, manually
# reviewed before being hashed. zarinpal/emofid/ramzinex were rendered
# with JavaScript disabled (_screenshot_bytes' default); the rest needed
# allow_javascript=True — their real login pages are JS-driven SPAs that
# render blank without it — which is safe here specifically because these
# are curated, human-picked URLs, never attacker/user-supplied input; see
# _screenshot_bytes' docstring. See conversation history for the full
# per-brand review notes (rejected candidates aren't listed here at all).
REFERENCE_HASHES = {
    "zarinpal": imagehash.hex_to_hash("b133c6cecc193939"),  # connect.zarinpal.com/login
    "emofid":   imagehash.hex_to_hash("c1cc966b6994966b"),  # login.emofid.com/Login
    "ramzinex": imagehash.hex_to_hash("88e0f46b87b361bc"),  # ramzinex.com/login
    "payping":  imagehash.hex_to_hash("a61c3ce3784e873c"),  # oauth.payping.ir/auth/number
    "vandar":   imagehash.hex_to_hash("e6ce8c2666cc3399"),  # account.vandar.io
    "zibal":    imagehash.hex_to_hash("f60e4ee3483c686b"),  # panel.zibal.ir/auth/login
    "jibit":    imagehash.hex_to_hash("b6249906db35cb5a"),  # dashboard.jibit.ir/auth/login
    "idpay":    imagehash.hex_to_hash("b0389a9a393175dd"),  # panel.idpay.ir/auth-user
    "digipay":  imagehash.hex_to_hash("a43098cf9b31679e"),  # app.mydigipay.com/auth/login
    "bitpin":   imagehash.hex_to_hash("c35d3c94c2d5bdc0"),  # bitpin.ir/login
    "paystar":  imagehash.hex_to_hash("bfccc039c8c7d0c5"),  # my.paystar.ir/login
    "bahamta":  imagehash.hex_to_hash("f25ac87272d8cc66"),  # webpay.bahamta.com/login
    "hesabit":  imagehash.hex_to_hash("c9ca6267c8c86f36"),  # www.hesabit.com/users/login
}


def build_reference_hash(local_image_path: str) -> str:
    """Run this offline against a manually-saved, trusted screenshot
    of a brand's real login page. Returns the hex string to paste into
    REFERENCE_HASHES. Deliberately does not fetch anything live."""
    with open(local_image_path, "rb") as f:
        return str(compute_phash(f.read()))


def find_closest_match(candidate_hash: imagehash.ImageHash):
    """Returns (brand_name, distance) for the closest reference, or
    (None, None) if REFERENCE_HASHES is empty."""
    if not REFERENCE_HASHES:
        return None, None

    best_brand, best_distance = None, None
    for brand, ref_hash in REFERENCE_HASHES.items():
        distance = candidate_hash - ref_hash  # imagehash overloads `-` as Hamming distance
        if best_distance is None or distance < best_distance:
            best_brand, best_distance = brand, distance

    return best_brand, best_distance


# ── public entry point ─────────────────────────────────────────────────

async def check_visual_similarity(
    url: str,
    include_screenshot: bool = False,
    settle_ms: int = 0,
    allow_javascript: bool = False,
) -> VisualCheckResult:
    """
    Main entry point for predict.py / app.py to call.

    include_screenshot: if True, the raw PNG bytes are kept on the
    result (VisualCheckResult.screenshot_png) so a caller can display
    the rendered page — e.g. in a SOC analyst UI reviewing a flagged
    URL. Defaults to False so batch/high-volume callers don't pay the
    memory/payload cost for images nobody will look at.

    settle_ms: passed straight through to _screenshot_bytes(). Leave at
    0 (default) for live candidate-URL checks. Only the offline
    reference-capture flow should set this — see _screenshot_bytes'
    docstring for why.

    allow_javascript: passed straight through to _screenshot_bytes().
    MUST stay False for every live candidate-URL check — see
    _screenshot_bytes' docstring. Only the curated, human-driven
    reference-capture flow may set this to True.

    IMPORTANT: a failure here must be surfaced as `checked=False` with
    a reason, never silently converted into "no match found" — that
    would let an attacker bypass this signal just by serving a page
    that crashes the renderer or times it out. signals.py should emit
    a VISUAL_CHECK_UNAVAILABLE code (not silence) when checked=False.
    """
    try:
        screenshot = await _screenshot_bytes(url, settle_ms=settle_ms, allow_javascript=allow_javascript)
    except UnsafeTargetError as e:
        return VisualCheckResult(checked=False, unavailable_reason=f"blocked_target: {e}")
    except RenderTimeoutError as e:
        return VisualCheckResult(checked=False, unavailable_reason=f"timeout: {e}")
    except RenderFailedError as e:
        return VisualCheckResult(checked=False, unavailable_reason=f"render_failed: {e}")

    phash = compute_phash(screenshot)
    brand, distance = find_closest_match(phash)

    return VisualCheckResult(
        checked=True,
        phash=str(phash),
        best_match_brand=brand,
        best_match_distance=distance,
        is_match=(distance is not None and distance <= MATCH_THRESHOLD),
        screenshot_png=screenshot if include_screenshot else None,
    )


# ── CLI for standalone testing ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 visual_similarity.py <url> [--save-screenshot out.png]")
        sys.exit(1)

    target_url = sys.argv[1]
    save_path = None
    if "--save-screenshot" in sys.argv:
        idx = sys.argv.index("--save-screenshot")
        save_path = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "screenshot.png"

    result = asyncio.run(check_visual_similarity(target_url, include_screenshot=bool(save_path)))

    print(f"\nURL: {target_url}")
    if not result.checked:
        print(f"  Check unavailable: {result.unavailable_reason}")
    else:
        print(f"  pHash: {result.phash}")
        if result.best_match_brand:
            print(f"  Closest brand match: {result.best_match_brand} (distance {result.best_match_distance})")
            print(f"  Visual match: {'YES' if result.is_match else 'no'}")
        else:
            print("  No reference hashes configured yet (REFERENCE_HASHES is empty)")

        if save_path and result.screenshot_png:
            with open(save_path, "wb") as f:
                f.write(result.screenshot_png)
            print(f"  Screenshot saved: {save_path}")
