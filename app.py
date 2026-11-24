"""
Safelink Bypasser - backend (FastAPI + Playwright async)

Instal:    pip install fastapi uvicorn playwright tldextract
           playwright install chromium
Jalankan:  python safelink_bypasser.py
Buka:      http://127.0.0.1:8000
"""
import asyncio
import contextlib
import ipaddress
import logging
import os
import re
import socket
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import tldextract
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from playwright.async_api import Browser, Error as PWError, Page, async_playwright

# --------------------------------------------------------------------------
# Konfigurasi
# --------------------------------------------------------------------------
MAX_CONCURRENT = 2        # jumlah proses bypass yang berjalan bersamaan
TOTAL_TIMEOUT = 120       # batas waktu total per permintaan (detik)
STEP_TIMEOUT = 35         # lama menunggu tombol/timer di satu halaman (detik)
PROBE_TIMEOUT = 7         # lama "mengintip" halaman baru sebelum dianggap tujuan akhir
MAX_CLICKS = 25           # batas total klik per permintaan

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Jenis resource yang tidak dibutuhkan (mempercepat + mengurangi iklan)
BLOCKED_RESOURCES = {"image", "media", "font"}

# Potongan nama host iklan / pop-up pihak ketiga yang diblokir
AD_HOST_KEYWORDS = (
    "doubleclick", "googlesyndication", "googleadservices", "adservice",
    "popads", "popcash", "propeller", "exoclick", "juicyads", "adsterra",
    "clickadu", "hilltopads", "onclickads", "onclkds", "adcash", "trafficjunky",
    "popunder", "adnxs", "taboola", "outbrain", "mgid", "revcontent",
    "pubmatic", "rubiconproject", "criteo", "adsco.re", "a-ads", "bidvertiser",
    "admaven", "ad-maven", "monetag", "richpush", "pushwhy", "profitablecpm",
    "highperformanceformat", "effectivegatecpm", "adskeeper", "yllix",
)

# Host tujuan yang pasti "akhir" (langsung berhenti, tidak dicari tombol lagi)
FINAL_DOMAINS = {
    "drive.google.com", "docs.google.com", "mega.nz", "mediafire.com",
    "dropbox.com", "t.me", "telegram.me", "github.com", "youtube.com",
    "youtu.be", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "play.google.com", "apps.apple.com", "sourceforge.net", "gofile.io",
    "pixeldrain.com", "terabox.com", "1drv.ms", "onedrive.live.com",
}

# Urutan prioritas teks tombol navigasi
PRIORITY_PATTERNS = [
    r"get\s*link",
    r"visit\s*(the\s*)?link",
    r"(open|unlock)\s*link",
    r"(go|continue)\s*to\s*(the\s*)?(link|destination|website|site)",
    r"\bcontinue\b",
    r"\bnext\b",
    r"\bproceed\b",
    r"\blanjut",
    r"\bskip\b",
]
PRIORITY_RES = [re.compile(p, re.I) for p in PRIORITY_PATTERNS]

# Tombol yang diabaikan (iklan, tombol timer berisi angka, dsb.)
EXCLUDE_RE = re.compile(
    r"(sign\s*up|log\s*in|subscribe|install|advert|\d|wait|tunggu|please)", re.I
)

COUNTDOWN_RE = re.compile(
    r"(please\s+wait|wait\s+\d|tunggu|\b\d+\s*(s|sec|secs|seconds|detik)\b|"
    r"countdown|generating|redirecting|getting\s+link|verifying)",
    re.I,
)

SELECTOR = (
    "a, button, input[type=button], input[type=submit], [role=button], "
    "div[onclick], span[onclick], [class*=btn], [id*=btn]"
)

JS_COLLECT = r"""
els => els.slice(0, 400).map((el, i) => {
  const r = el.getBoundingClientRect();
  const cs = getComputedStyle(el);
  const visible = r.width > 0 && r.height > 0 && cs.visibility !== 'hidden'
                  && cs.display !== 'none' && parseFloat(cs.opacity) > 0.2;
  const disabled = !!el.disabled
                  || el.getAttribute('aria-disabled') === 'true'
                  || /(^|\s)disabled(\s|$)/.test(String(el.className || ''))
                  || cs.pointerEvents === 'none';
  const label = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
  return { i, visible, disabled, label: label.slice(0, 80) };
})
"""

INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.open = () => null;   // blokir pop-up/pop-under
"""

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("safelink")

_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline


# --------------------------------------------------------------------------
# Utilitas
# --------------------------------------------------------------------------
class BypassError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.message = message
        self.status = status


def reg_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return _tld(url).registered_domain or host


def is_ad_host(host: str) -> bool:
    return any(k in host for k in AD_HOST_KEYWORDS)


_dns_cache: dict[str, bool] = {}


async def host_is_public(host: str | None) -> bool:
    """Tolak localhost / IP privat agar server tidak bisa dipakai menyerang jaringan lokal (SSRF)."""
    if not host:
        return False
    host = host.lower()
    if host in _dns_cache:
        return _dns_cache[host]

    ips = []
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            ips = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
        except (socket.gaierror, ValueError):
            ips = []  # tidak resolve -> browser akan gagal sendiri

    ok = not any(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        for ip in ips
    )
    if len(_dns_cache) > 2000:
        _dns_cache.clear()
    _dns_cache[host] = ok
    return ok


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048:
        raise HTTPException(400, "URL kosong atau terlalu panjang.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise HTTPException(
            400, "URL tidak valid. Gunakan alamat yang diawali http:// atau https://."
        )
    return raw


def pick_button(infos: list[dict]) -> dict | None:
    cands = [
        x for x in infos
        if x["visible"] and not x["disabled"]
        and 0 < len(x["label"]) <= 40
        and not EXCLUDE_RE.search(x["label"])
    ]
    for rx in PRIORITY_RES:
        for x in cands:
            if rx.search(x["label"]):
                return x
    return None


async def looks_like_countdown(page: Page) -> bool:
    text = await page.evaluate(
        "() => (document.body ? document.body.innerText : '').slice(0, 6000)"
    )
    return bool(COUNTDOWN_RE.search(text))


async def wait_for_action(page: Page, patient: bool):
    """Tunggu sampai ada tombol yang bisa diklik.
    Mengembalikan: dict tombol | "navigated" | None (tidak ada tombol)."""
    start_url = page.url
    t0 = time.monotonic()
    tick = 0
    countdown = False
    while True:
        if page.url != start_url:
            return "navigated"
        try:
            infos = await page.locator(SELECTOR).evaluate_all(JS_COLLECT)
            hit = pick_button(infos)
            if hit:
                return hit
            if tick % 2 == 0:
                countdown = await looks_like_countdown(page)
            if tick % 3 == 2:
                await page.mouse.wheel(0, 700)  # sebagian situs baru memunculkan tombol setelah scroll
        except PWError:
            pass  # halaman sedang berpindah
        tick += 1
        limit = STEP_TIMEOUT if (patient or countdown) else PROBE_TIMEOUT
        if time.monotonic() - t0 >= limit:
            return None
        await asyncio.sleep(0.7)


async def click_element(page: Page, idx: int) -> None:
    loc = page.locator(SELECTOR).nth(idx)
    try:
        await loc.evaluate(
            "el => { if (el.tagName === 'A') el.removeAttribute('target'); }",
            timeout=3000,
        )
        await loc.scroll_into_view_if_needed(timeout=3000)
        await loc.click(timeout=5000)
    except PWError:
        with contextlib.suppress(PWError):
            await loc.evaluate("el => el.click()", timeout=3000)


async def settle(page: Page) -> None:
    await asyncio.sleep(1.5)
    with contextlib.suppress(PWError):
        await page.wait_for_load_state("domcontentloaded", timeout=5000)


# --------------------------------------------------------------------------
# Inti proses bypass
# --------------------------------------------------------------------------
async def bypass(browser: Browser, url: str, steps: list[str]) -> str:
    context = await browser.new_context(
        user_agent=USER_AGENT,
        viewport={"width": 1366, "height": 768},
        locale="en-US",
        service_workers="block",
    )
    bg_tasks: set[asyncio.Task] = set()

    def spawn(coro) -> None:
        t = asyncio.create_task(coro)
        bg_tasks.add(t)
        t.add_done_callback(bg_tasks.discard)

    try:
        await context.add_init_script(INIT_SCRIPT)
        page = await context.new_page()
        nav_attempts: list[str] = []

        async def route_handler(route):
            req = route.request
            try:
                parsed = urlparse(req.url)
                host = (parsed.hostname or "").lower()
                if (
                    parsed.scheme not in ("http", "https")
                    or req.resource_type in BLOCKED_RESOURCES
                    or is_ad_host(host)
                    or not await host_is_public(host)
                ):
                    return await route.abort()
                if req.is_navigation_request() and req.frame == page.main_frame:
                    nav_attempts.append(req.url)
                await route.continue_()
            except PWError:
                pass

        await context.route("**/*", route_handler)

        # Tutup semua tab pop-up yang terbuka
        async def close_popup(p: Page):
            with contextlib.suppress(PWError):
                await p.close()

        context.on("page", lambda p: spawn(close_popup(p)) if p is not page else None)

        async def accept_dialog(d):
            with contextlib.suppress(PWError):
                await d.accept()

        page.on("dialog", lambda d: spawn(accept_dialog(d)))

        last_logged = {"url": ""}

        def on_nav(frame):
            if frame == page.main_frame and frame.url.startswith("http") \
                    and frame.url != last_logged["url"]:
                last_logged["url"] = frame.url
                steps.append(f"Halaman: {frame.url[:140]}")

        page.on("framenavigated", on_nav)

        # ----- mulai -----
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        except PWError as e:
            raise BypassError(
                f"Gagal membuka link: {str(e).splitlines()[0]}", 502
            )

        start_domain = reg_domain(url)
        clicks = 0
        last_click_url = ""

        def final_url() -> str:
            u = page.url
            if not u.startswith("http") and nav_attempts:
                u = nav_attempts[-1]
            return u

        while True:
            if page.is_closed():
                raise BypassError("Halaman tertutup tidak terduga.", 502)

            cur = page.url
            if not cur.startswith(("http", "chrome-error")):
                await asyncio.sleep(1)
                continue

            dom = reg_domain(cur)
            if dom != start_domain and dom in FINAL_DOMAINS:
                return cur

            action = await wait_for_action(page, patient=(dom == start_domain))
            if action == "navigated":
                continue
            if action is None:
                if dom != start_domain or cur.startswith("chrome-error"):
                    return final_url()  # tidak ada tombol lagi di domain baru -> tujuan akhir
                raise BypassError(
                    "Tombol navigasi (Continue / Get Link / dll.) tidak ditemukan "
                    "di halaman. Situs ini mungkin memakai captcha atau pola yang belum didukung.",
                    502,
                )

            if clicks >= MAX_CLICKS:
                raise BypassError(
                    "Terlalu banyak langkah tanpa hasil. Link kemungkinan butuh captcha "
                    "atau interaksi manual.", 502,
                )
            if cur == last_click_url:
                await asyncio.sleep(2.5)  # beri waktu timer berjalan
            clicks += 1
            last_click_url = cur
            steps.append(f"Klik: “{action['label']}”")
            await click_element(page, action["i"])
            await settle(page)
    finally:
        for t in list(bg_tasks):
            t.cancel()
        with contextlib.suppress(Exception):
            await context.close()


# --------------------------------------------------------------------------
# Frontend (HTML disematkan)
# --------------------------------------------------------------------------
INDEX_HTML = r'''<!DOCTYPE html>
<html lang="id" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Safelink Bypasser</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            base: '#0e1422',
            panel: '#151d30',
            edge: '#26324b',
            ink: '#e9edf6',
            mute: '#8f9bb5',
            amber: { DEFAULT: '#f0b54a', deep: '#1b1405' },
            rose: { soft: '#f28b9b' }
          },
          fontFamily: {
            sans: ['"Bricolage Grotesque"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']
          }
        }
      }
    }
  </script>
  <style>
    html { color-scheme: dark; }
    body { background: #0e1422; }
    :focus-visible { outline: 2px solid #f0b54a; outline-offset: 2px; }
  </style>
</head>
<body class="min-h-screen bg-base text-ink font-sans antialiased">
  <div class="mx-auto flex min-h-screen w-full max-w-2xl flex-col px-5 py-8 sm:py-14">

    <header class="flex items-center gap-2.5">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f0b54a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M10 13a5 5 0 0 0 7.07 0l3-3a5 5 0 0 0-7.07-7.07l-1 1"/>
        <path d="M14 11a5 5 0 0 0-7.07 0l-3 3a5 5 0 0 0 7.07 7.07l1-1"/>
      </svg>
      <span class="text-base font-semibold tracking-tight">Safelink Bypasser</span>
    </header>

    <main class="mt-12 flex-1 sm:mt-20">
      <h1 class="text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
        Langsung ke tujuan, tanpa halaman perantara.
      </h1>
      <p class="mt-4 max-w-xl text-base leading-relaxed text-mute">
        Tempel link dari move2link, khaddavi, atau safelink sejenis. Server akan menunggu timer, menekan tombol lanjut, lalu mengambil alamat akhirnya.
      </p>

      <form id="form" class="mt-9" novalidate>
        <label for="url" class="mb-2 block text-sm font-medium text-mute">URL safelink</label>
        <div class="flex flex-col gap-3 sm:flex-row">
          <input id="url" type="url" inputmode="url" autocomplete="off" spellcheck="false"
                 placeholder="https://move2link.com/abc123"
                 class="min-w-0 flex-1 rounded-xl border border-edge bg-panel px-4 py-3.5 text-base text-ink placeholder:text-mute/60 focus:border-amber focus:outline-none focus:ring-1 focus:ring-amber">
          <button id="submit" type="submit"
                  class="inline-flex items-center justify-center rounded-xl bg-amber px-6 py-3.5 text-base font-semibold text-amber-deep transition hover:brightness-110 active:brightness-95 disabled:cursor-not-allowed disabled:opacity-60">
            Bypass Link
          </button>
        </div>
      </form>

      <div id="status" class="mt-6" aria-live="polite">

        <!-- Loading -->
        <section id="loading" class="hidden rounded-xl border border-edge bg-panel p-5">
          <div class="flex items-center gap-4">
            <div class="h-6 w-6 shrink-0 animate-spin rounded-full border-2 border-edge border-t-amber motion-reduce:animate-none" aria-hidden="true"></div>
            <div>
              <p class="font-medium">Memproses link… <span id="elapsed" class="font-mono text-sm text-amber">0 dtk</span></p>
              <p class="mt-1 text-sm text-mute">Browser di server sedang menunggu timer dan menekan tombol. Biasanya 10–60 detik.</p>
            </div>
          </div>
        </section>

        <!-- Hasil -->
        <section id="result" class="hidden rounded-xl border border-edge bg-panel p-5">
          <p class="text-sm font-medium text-amber">Tujuan akhir ditemukan</p>
          <p id="finalUrl" class="mt-3 break-all rounded-lg border border-edge bg-base px-4 py-3 font-mono text-sm leading-relaxed"></p>
          <div class="mt-4 flex flex-col gap-3 sm:flex-row">
            <button id="copyBtn" type="button"
                    class="inline-flex flex-1 items-center justify-center rounded-xl border border-edge px-5 py-3 font-medium transition hover:border-amber hover:text-amber">
              Copy Link
            </button>
            <a id="openBtn" href="#" target="_blank" rel="noopener noreferrer"
               class="inline-flex flex-1 items-center justify-center rounded-xl bg-amber px-5 py-3 font-semibold text-amber-deep transition hover:brightness-110">
              Buka Link
            </a>
          </div>
          <details class="mt-5 text-sm text-mute">
            <summary class="cursor-pointer select-none py-1 hover:text-ink">Lihat langkah yang dilalui</summary>
            <ol id="steps" class="mt-3 space-y-2 border-l border-edge pl-4"></ol>
            <p id="meta" class="mt-3 text-xs"></p>
          </details>
        </section>

        <!-- Error -->
        <section id="error" role="alert" class="hidden rounded-xl border border-rose-soft/40 bg-panel p-5">
          <p class="font-medium text-rose-soft">Link gagal diproses</p>
          <p id="errorMsg" class="mt-2 text-sm leading-relaxed"></p>
          <p class="mt-3 text-sm text-mute">Periksa bahwa link masih aktif dan lengkap, lalu coba lagi. Situs dengan captcha belum bisa diproses otomatis.</p>
        </section>
      </div>
    </main>

    <footer class="mt-14 text-sm text-mute">
      Gunakan hanya untuk link yang memang boleh kamu akses.
    </footer>
  </div>

  <script>
    const $ = (id) => document.getElementById(id);
    const form = $('form'), input = $('url'), submitBtn = $('submit');
    const panels = { loading: $('loading'), result: $('result'), error: $('error') };
    let tick = null;

    function show(name) {
      for (const [k, el] of Object.entries(panels)) el.classList.toggle('hidden', k !== name);
    }

    function setLoading(on) {
      submitBtn.disabled = on;
      input.disabled = on;
      submitBtn.textContent = on ? 'Memproses…' : 'Bypass Link';
      clearInterval(tick);
      if (on) {
        show('loading');
        const t0 = Date.now();
        $('elapsed').textContent = '0 dtk';
        tick = setInterval(() => {
          $('elapsed').textContent = Math.floor((Date.now() - t0) / 1000) + ' dtk';
        }, 500);
      }
    }

    function showError(msg) {
      $('errorMsg').textContent = msg;
      show('error');
    }

    function showResult(data) {
      const url = String(data.final_url || '');
      if (!/^https?:\/\//i.test(url)) {
        showError('Server mengembalikan hasil yang tidak valid.');
        return;
      }
      $('finalUrl').textContent = url;
      $('openBtn').href = url;
      const list = $('steps');
      list.replaceChildren();
      (data.steps || []).forEach((s) => {
        const li = document.createElement('li');
        li.textContent = s;
        li.className = 'break-all';
        list.appendChild(li);
      });
      $('meta').textContent = 'Selesai dalam ' + data.elapsed + ' detik.';
      $('copyBtn').textContent = 'Copy Link';
      show('result');
    }

    async function copyText(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch {}
        ta.remove();
        return ok;
      }
    }

    $('copyBtn').addEventListener('click', async () => {
      const btn = $('copyBtn');
      const ok = await copyText($('finalUrl').textContent);
      btn.textContent = ok ? 'Tersalin' : 'Gagal menyalin';
      setTimeout(() => (btn.textContent = 'Copy Link'), 1800);
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      let url = input.value.trim();
      if (!url) {
        showError('Kolom masih kosong. Tempel URL safelink terlebih dahulu.');
        return;
      }
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = 'https://' + url;
      try { new URL(url); } catch {
        showError('Format URL tidak valid. Contoh: https://move2link.com/abc123');
        return;
      }

      setLoading(true);
      const controller = new AbortController();
      const abortTimer = setTimeout(() => controller.abort(), 150000);
      try {
        const res = await fetch('/api/bypass', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
          signal: controller.signal
        });
        let data = {};
        try { data = await res.json(); } catch {}
        if (!res.ok) {
          const msg = typeof data.detail === 'string'
            ? data.detail
            : 'Server mengembalikan error ' + res.status + '.';
          throw new Error(msg);
        }
        setLoading(false);
        showResult(data);
      } catch (err) {
        setLoading(false);
        if (err.name === 'AbortError') {
          showError('Server terlalu lama merespons. Coba lagi beberapa saat.');
        } else if (err instanceof TypeError) {
          showError('Tidak bisa terhubung ke server. Pastikan app.py masih berjalan.');
        } else {
          showError(err.message);
        }
      } finally {
        clearTimeout(abortTimer);
      }
    });
  </script>
</body>
</html>
'''


# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    pw = await async_playwright().start()
    app.state.browser = await pw.chromium.launch(
        headless=True,
        args=["--disable-blink-features=AutomationControlled"]
        + (["--no-sandbox"] if os.environ.get("NO_SANDBOX") else []),
    )
    app.state.sem = asyncio.Semaphore(MAX_CONCURRENT)
    log.info("Browser siap. Buka http://127.0.0.1:8000")
    yield
    await app.state.browser.close()
    await pw.stop()


app = FastAPI(title="Safelink Bypasser", lifespan=lifespan)


class BypassRequest(BaseModel):
    url: str


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/bypass")
async def api_bypass(req: BypassRequest):
    url = normalize_url(req.url)
    if not await host_is_public(urlparse(url).hostname):
        raise HTTPException(400, "Alamat lokal / privat tidak diizinkan.")

    started = time.monotonic()
    steps: list[str] = []
    log.info("Bypass: %s", url)
    try:
        async with app.state.sem:
            final = await asyncio.wait_for(
                bypass(app.state.browser, url, steps), TOTAL_TIMEOUT
            )
    except asyncio.TimeoutError:
        raise HTTPException(
            504,
            f"Waktu habis setelah {TOTAL_TIMEOUT} detik. Timer di situs terlalu lama "
            "atau halaman butuh interaksi manual.",
        )
    except BypassError as e:
        log.warning("Gagal: %s", e.message)
        raise HTTPException(e.status, e.message)
    except PWError as e:
        log.warning("Playwright error: %s", e)
        raise HTTPException(502, f"Kesalahan browser: {str(e).splitlines()[0]}")
    except Exception:
        log.exception("Error tak terduga")
        raise HTTPException(500, "Terjadi kesalahan internal pada server.")

    steps.append(f"Hasil: {final[:140]}")
    return {
        "success": True,
        "final_url": final,
        "elapsed": round(time.monotonic() - started, 1),
        "steps": steps,
    }


if __name__ == "__main__":
    import uvicorn

    # Jangan pakai reload=True di Windows: Playwright butuh ProactorEventLoop.
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
