"""Подписчики наших страниц из официального Instagram Graph API — независимо от сервера со скрейперами.

Запускается раз в час в GitHub Actions (.github/workflows/graph-live.yml): машины GitHub за границей,
поэтому ни VPN, ни наш сервер не нужны. Берёт уже выложенные data/live.enc и data/network.enc, вписывает
свежие цифры API (подписчики, число постов, последние посты) и шифрует обратно — сайт показывает их как обычно.
Вернулся сервер — его полная выгрузка перекрывает эти файлы.

Секреты репозитория (Settings → Secrets and variables → Actions):
  GRAPH_TOKENS   токены приложения Meta (как в data/graph_api.json сборщика), через перевод строки или запятую
  AKM_SITE_PIN   пинкод сайта (им зашифрованы data/*.enc)
Список страниц берётся из самих зашифрованных данных — в открытом репозитории его нет.
Только стандартная библиотека Python.
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parents[2] / "data"
API = "https://graph.facebook.com/v21.0"
MSK = timezone(timedelta(hours=3))
USAGE_STOP = 70          # % лимита приложения: дальше не идём — лимит общий с сервером
MEDIA_EVERY_H = 3        # посты — раз в 3 ч (тяжёлый запрос), подписчики — каждый час
MEDIA_PER_ACC = 15
CODE_RE = re.compile(r"/(?:p|reel|tv)/([A-Za-z0-9_-]+)")

# ---- шифрование сайта (как site_crypto.py сборщика и gate.js) ----
SALT, ITER, MAGIC = b"akm-ig-radar-v1", 150_000, b"AKM1"


def key(pin: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), SALT, ITER, 32)


def _stream(k: bytes, nonce: bytes, n: int) -> bytes:
    return b"".join(hashlib.sha256(k + nonce + i.to_bytes(4, "big")).digest() for i in range((n + 31) // 32))[:n]


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big") if a else b""


def encrypt(data: bytes, k: bytes) -> bytes:
    nonce = os.urandom(16)
    return MAGIC + nonce + hashlib.sha256(k + nonce + b"ok").digest()[:16] + _xor(data, _stream(k, nonce, len(data)))


def decrypt(blob: bytes, k: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("не файл AKM1")
    nonce, check, ct = blob[4:20], blob[20:36], blob[36:]
    if hashlib.sha256(k + nonce + b"ok").digest()[:16] != check:
        raise ValueError("неверный пинкод (AKM_SITE_PIN)")
    return _xor(ct, _stream(k, nonce, len(ct)))


def load(name: str, k: bytes):
    return json.loads(decrypt((DATA / f"{name}.enc").read_bytes(), k).decode("utf-8"))


def save(name: str, data, k: bytes) -> None:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (DATA / f"{name}.enc").write_bytes(encrypt(raw, k))


# ---- Graph API ----
class Stop(Exception):
    pass


class Api:
    def __init__(self):
        self.usage = self.calls = 0

    def get(self, path: str, token: str, **params) -> dict:
        if self.usage >= USAGE_STOP:
            raise Stop(f"лимит приложения {self.usage}%")
        url = f"{API}/{path}?{urllib.parse.urlencode({**params, 'access_token': token})}"
        try:
            with urllib.request.urlopen(url, timeout=40) as r:
                self.calls += 1
                self._usage(r.headers)
                return json.load(r)
        except urllib.error.HTTPError as e:
            self.calls += 1
            self._usage(e.headers)
            try:
                err = json.load(e).get("error", {})
                return {"error": f"{err.get('code', e.code)}: {err.get('message', '')}"[:200]}
            except Exception:  # noqa: BLE001
                return {"error": f"HTTP {e.code}"}

    def _usage(self, headers) -> None:
        keys = ("call_count", "total_cputime", "total_time")
        try:
            vals = [int(json.loads(headers.get("x-app-usage") or "{}").get(k, 0)) for k in keys]
            for items in json.loads(headers.get("x-business-use-case-usage") or "{}").values():
                vals += [int(x.get(k, 0)) for x in items for k in keys]
            self.usage = max(vals or [0])
        except Exception:  # noqa: BLE001
            pass


def country() -> str:
    try:
        with urllib.request.urlopen("https://api.country.is/", timeout=10) as r:
            return (json.load(r).get("country") or "?").upper()
    except Exception:  # noqa: BLE001
        return "?"


def pick_token(api: Api, tokens: list[str], probe: str) -> tuple[str, str]:
    """(ig_id, токен), с которых проходит business_discovery (у части токенов нет нужных прав)."""
    for t in tokens:
        r = api.get("me/assigned_instagram_accounts", t, fields="id,username", limit=100)
        for a in r.get("data", []):
            if "error" not in api.get(a["id"], t, fields=f"business_discovery.username({probe}){{id}}"):
                return a["id"], t
    raise Stop("ни один токен не дал business_discovery — проверьте секрет GRAPH_TOKENS")


def post(m: dict) -> dict:
    taken = datetime.strptime(m["timestamp"], "%Y-%m-%dT%H:%M:%S%z").astimezone(MSK) if m.get("timestamp") else None
    return {"c": (CODE_RE.search(m.get("permalink") or "") or [None, None])[1],
            "k": "reel" if m.get("media_product_type") == "REELS" else
                 ("carousel" if m.get("media_type") == "CAROUSEL_ALBUM" else "post"),
            "t": taken.isoformat(timespec="minutes") if taken else None,
            "l": m.get("like_count"), "cm": m.get("comments_count"), "v": m.get("view_count"),
            "x": (m.get("caption") or "")[:120]}


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    tokens = [t.strip() for t in re.split(r"[\s,]+", os.environ.get("GRAPH_TOKENS", "")) if t.strip()]
    pin = os.environ.get("AKM_SITE_PIN", "").strip()
    if not tokens or not pin:
        print("нет секретов GRAPH_TOKENS / AKM_SITE_PIN — пропуск")
        return 0
    c = country()
    if c in ("RU", "?"):
        print(f"выход {c}: к Meta с российского/неизвестного IP не обращаемся")
        return 1
    k = key(pin)
    live, net = load("live", k), load("network", k)
    users = [a[0] for a in live.get("acc", [])]
    if not users:
        print("в live.enc нет страниц")
        return 1

    now = datetime.now(MSK)
    with_media = now.hour % MEDIA_EVERY_H == 0
    api = Api()
    got, errs = {}, []
    try:
        me_id, tok = pick_token(api, tokens, users[0])
        for u in users:
            f = ("business_discovery.username(" + u + "){id,followers_count,follows_count,media_count"
                 + (f",media.limit({MEDIA_PER_ACC}){{id,caption,media_type,media_product_type,timestamp,permalink,"
                    "like_count,comments_count,view_count}" if with_media else "") + "}")
            r = api.get(me_id, tok, fields=f)
            if "error" in r:
                errs.append(f"{u}: {r['error'][:80]}")
                continue
            got[u] = r["business_discovery"]
    except Stop as e:
        print(f"остановлен: {e}")
    if not got:
        print("ни одной страницы не получено; " + "; ".join(errs[:5]))
        return 1

    ts, at = int(now.timestamp()), now.isoformat(timespec="minutes")
    today = now.date().isoformat()

    # live.enc / network.live: [username, подписчики, время замера, скорость/ч] — скорость оставляем серверную
    def patch_live(lv: dict) -> None:
        for a in lv.get("acc", []):
            b = got.get(a[0])
            if b and b.get("followers_count") is not None and ts > (a[2] or 0):
                a[1], a[2] = b["followers_count"], ts
        lv["at"] = max(lv.get("at") or 0, ts)

    patch_live(live)
    if isinstance(net.get("live"), dict):
        patch_live(net["live"])

    # network.graph: подписчики/посты API (закрытую статистику ins, если была от сервера, не трогаем)
    g = net.setdefault("graph", {"at": at, "acc": {}}) or {"at": at, "acc": {}}
    net["graph"] = g
    for u, b in got.items():
        x = g.setdefault("acc", {}).setdefault(u, {})
        x.update({"f": b.get("followers_count"), "media": b.get("media_count"), "at": at})
        if with_media:
            x["posts"] = [post(m) for m in (b.get("media") or {}).get("data", [])]
    g["at"] = at

    # таблица по дням (понедельники!): сегодняшний день — подписчики из API
    days = net.get("days") or []
    day = next((d for d in days if d.get("date") == today), None)
    if day is None and days:
        prev = days[-1]
        day = {"date": today, "collectedAt": at, "stats": {
            u: {"group": s.get("group"), "ok": True, "followers": s.get("followers"), "following": s.get("following"),
                "posts": []} for u, s in (prev.get("stats") or {}).items()}}
        days.append(day)
    if day is not None:
        for u, b in got.items():
            s = day.setdefault("stats", {}).get(u)
            if s is not None:
                s["followers"], s["ok"] = b.get("followers_count"), True
                if b.get("follows_count") is not None:
                    s["following"] = b["follows_count"]
        day["collectedAt"] = max(day.get("collectedAt") or "", at)
    net["updatedAt"] = max(net.get("updatedAt") or "", at)
    net["apiAt"] = at

    save("live", live, k)
    save("network", net, k)
    print(f"API: {len(got)}/{len(users)} страниц{', с постами' if with_media else ''} · запросов {api.calls}, "
          f"лимит {api.usage}% · выход {c}" + (f" · ошибки: {'; '.join(errs[:3])}" if errs else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
