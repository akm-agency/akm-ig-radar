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
USAGE_STOP_ALONE = 95    # сервер молчит > 3 ч — лимит тратим только мы (12.11 стоп на 70% оставил дыру 12–16 ч)
MEDIA_EVERY_H = 3        # посты — раз в 3 ч (тяжёлый запрос), подписчики — каждый час
MEDIA_PER_ACC = 8
MEDIA_USAGE_MAX = 50     # посты — вторым проходом и только пока лимит ниже: подписчики важнее
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
    def __init__(self, stop: int = USAGE_STOP):
        self.usage = self.calls = 0
        self.stop = stop

    def get(self, path: str, token: str, **params) -> dict:
        if self.usage >= self.stop:
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


LIMIT_RE = re.compile(r"^(4|17|32|613|80001|80002):|limit|too many", re.I)


def pick_token(api: Api, tokens: list[str], probes: list[str]) -> tuple[str, str]:
    """(ig_id, токен), с которых проходит business_discovery (у части токенов нет нужных прав).
    Пробуем на нескольких страницах: одна может быть закрыта/переименована."""
    limited = False
    for t in tokens:
        r = api.get("me/assigned_instagram_accounts", t, fields="id,username", limit=100)
        limited |= bool(LIMIT_RE.search(r.get("error", "") or ""))
        for a in r.get("data", []):
            for u in probes:
                x = api.get(a["id"], t, fields=f"business_discovery.username({u}){{id}}")
                if "error" not in x:
                    return a["id"], t
                limited |= bool(LIMIT_RE.search(x["error"]))
    if limited:
        raise Stop("лимит запросов приложения Meta (общий с сервером) — пропускаю этот час")
    raise BadConfig("ни один токен не дал business_discovery — проверьте секрет GRAPH_TOKENS")


class BadConfig(Exception):
    pass


def post(m: dict) -> dict:
    taken = datetime.strptime(m["timestamp"], "%Y-%m-%dT%H:%M:%S%z").astimezone(MSK) if m.get("timestamp") else None
    return {"c": (CODE_RE.search(m.get("permalink") or "") or [None, None])[1],
            "k": "reel" if m.get("media_product_type") == "REELS" else
                 ("carousel" if m.get("media_type") == "CAROUSEL_ALBUM" else "post"),
            "t": taken.isoformat(timespec="minutes") if taken else None,
            "l": m.get("like_count"), "cm": m.get("comments_count"), "v": m.get("view_count"),
            "x": (m.get("caption") or "")[:120]}


STALE_H = 3
SERVER_FRESH_MIN = 70   # сервер выгружал позже — сайт обновляет он
API_EVERY_MIN = 50      # без почасового графика — не чаще раза в час; с ним правило по слоту часа (hour_missing)


def forced_run() -> bool:
    """Запуск руками (кнопка или run-now.txt в main) — делаем сразу и письмо не откладываем."""
    ev = os.environ.get("GITHUB_EVENT_NAME")
    return ev == "workflow_dispatch" or (ev == "push" and os.environ.get("GITHUB_REF_NAME") == "main")


def age_min(get, now: datetime) -> float:
    """Сколько минут назад (∞, если не прочитать)."""
    try:
        return (now - datetime.fromisoformat(get())).total_seconds() / 60
    except Exception:  # noqa: BLE001
        return float("inf")


def hour_missing(net: dict, users: list[str], now: datetime) -> list[str] | None:
    """Страницы без замера в слоте текущего часа почасового графика (network.hourly); None — графика нет.
    Окно ещё не сдвинуто до текущего часа — значит, замеров в нём нет ни у кого."""
    hr = net.get("hourly")
    if not (isinstance(hr, dict) and hr.get("start") and isinstance(hr.get("acc"), dict)):
        return None
    try:
        start = datetime.fromisoformat(hr["start"]).replace(tzinfo=MSK)
    except (TypeError, ValueError):
        return None
    i = int((now.replace(minute=0, second=0, microsecond=0) - start).total_seconds() // 3600)

    def has(u: str) -> bool:
        f = (hr["acc"].get(u) or {}).get("f") or []
        return 0 <= i < len(f) and f[i] is not None
    return [u for u in users if not has(u)]


def server_check(k: bytes, now: datetime) -> None:
    """Сервер давно не выгружал (data/health.enc пишет только он) — помечаем, и workflow завершится ошибкой:
    GitHub сам пришлёт письмо о сбое. Так о поломке узнают сразу, а не через сутки."""
    try:
        at = datetime.fromisoformat(load("health", k)["at"])
        hours = (now - at).total_seconds() / 3600
    except Exception as e:  # noqa: BLE001
        hours, at = None, f"не прочитать health.enc: {e}"
    if hours is None or hours > STALE_H:
        if not (now.hour % 3 == 0 and now.minute < 20) and not forced_run():
            print(f"сервер молчит {hours or 0:.1f} ч (письмо — раз в 3 ч, в начале часа, кратного 3)")
            return
        msg = (f"СЕРВЕР НЕ ВЫГРУЖАЕТ ДАННЫЕ: последняя выгрузка {at} ({hours:.1f} ч назад)" if hours is not None else str(at)) + \
              ". Подписчики наших страниц идут из API, остальная статистика (конкуренты, радар) стоит. " \
              "Проверьте сервер: окно сборщика, VPN, data/run.log."
        print(msg)
        flag = Path(os.environ.get("RUNNER_TEMP", ".")) / "server_stale.txt"
        flag.write_text(msg, encoding="utf-8")
    else:
        print(f"сервер выгружал {hours:.1f} ч назад — ок")


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
    ev = os.environ.get("GITHUB_EVENT_NAME")
    # кнопка или run-now.txt в main — принудительно; пинок с ПК (ветка graph-kick) и расписание — по правилам ниже
    forced = ev == "workflow_dispatch" or (ev == "push" and os.environ.get("GITHUB_REF_NAME") == "main")
    server_age = age_min(lambda: load("health", k)["at"], now)
    if not forced and server_age < SERVER_FRESH_MIN:
        print(f"сервер выгружал {server_age:.0f} мин назад — он и обновляет сайт, API не трогаю (лимит Meta общий)")
        return 0
    hour = now.strftime("%Y-%m-%dT%H")
    prev_bad = net.get("apiBad") if isinstance(net.get("apiBad"), dict) else {}
    bad = set(prev_bad.get("u") or []) if prev_bad.get("h") == hour else set()
    targets, partial = users, False
    missing = None if forced else hour_missing(net, users, now)
    if missing is None and not forced:   # почасового графика нет — старое правило: не чаще раза в 50 мин
        api_age = age_min(lambda: net.get("apiAt"), now)
        if api_age < API_EVERY_MIN:
            print(f"цифры API обновлены {api_age:.0f} мин назад — следующие через час")
            server_check(k, now)
            return 0
    elif missing is not None:
        # 10.11 часы заполнялись не целиком (19:00 — 4 из 38): запуск упирался в лимит Meta на середине списка,
        # а правило «раз в 50 мин» не давало добрать остальных в тот же час. Теперь каждый пинок (15 мин)
        # добирает только страницы без замера в текущем часе; страницы с ошибкой API — один раз за час.
        retry = [u for u in missing if u not in bad]
        if not retry:
            print(f"в {now:%H}:00 замеры есть у {len(users) - len(missing)}/{len(users)} страниц"
                  + (f"; с ошибкой API (повтор в следующем часе): {', '.join(sorted(missing))}" if missing else ""))
            server_check(k, now)
            return 0
        partial = len(missing) < len(users)
        targets = retry
        if partial:
            print(f"в {now:%H}:00 нет замера у {len(missing)}/{len(users)} страниц — добираю {len(retry)}: {', '.join(retry)}")
    with_media = now.hour % MEDIA_EVERY_H == 0
    api = Api(USAGE_STOP_ALONE if server_age > STALE_H * 60 else USAGE_STOP)

    def journal(got_n: int, note: str) -> None:
        """Журнал запусков в зашифрованном network.enc (логи Actions без входа в GitHub не прочитать)."""
        runs = net.get("apiRuns") if isinstance(net.get("apiRuns"), list) else []
        runs.append([now.strftime("%d.%m %H:%M"), len(targets), got_n, api.usage, api.calls, note[:160]])
        net["apiRuns"] = runs[-96:]
    got, errs, new_bad = {}, [], set()
    done: set[str] = set()
    try:
        # проба токена — на уже замеренных в этом часе (они точно отвечают), потом на самих добираемых
        probes = ([u for u in users if u not in targets and u not in bad][:3] + targets[:3])[:3]
        me_id, tok = pick_token(api, tokens, probes)
        for u in targets:
            # только подписчики — лёгкий запрос. 12.11 посты в том же запросе выедали лимит Meta по времени
            # (total_time 97%) в часы 12/15/…, и почасовой замер подписчиков пропадал целиком
            f = "business_discovery.username(" + u + "){id,followers_count,follows_count,media_count}"
            r = api.get(me_id, tok, fields=f)
            done.add(u)
            if "error" in r:
                errs.append(f"{u}: {r['error'][:80]}")
                if not LIMIT_RE.search(r["error"]):
                    new_bad.add(u)
                elif sum(1 for x in errs[-3:] if LIMIT_RE.search(x.split(": ", 1)[-1])) >= 3:
                    raise Stop("Meta ответила «лимит» 3 раза подряд")   # не жжём запросы впустую, добор — следующий пинок
                continue
            got[u] = r["business_discovery"]
        if with_media:   # посты — вторым проходом, раз в 3 ч на страницу, пока запас лимита есть
            gacc = (net.get("graph") or {}).get("acc") or {}
            for u in list(got):
                if api.usage >= MEDIA_USAGE_MAX:
                    print(f"  посты отложены: лимит {api.usage}%")
                    break
                if age_min(lambda: gacc.get(u, {}).get("postsAt"), now) < MEDIA_EVERY_H * 60 - 20:
                    continue
                r = api.get(me_id, tok, fields=f"business_discovery.username({u}){{media.limit({MEDIA_PER_ACC})"
                            "{id,caption,media_type,media_product_type,timestamp,permalink,"
                            "like_count,comments_count,view_count}}")
                if "error" not in r:
                    got[u]["media"] = r["business_discovery"].get("media") or {"data": []}
    except Stop as e:
        print(f"остановлен: {e}")
    except BadConfig as e:
        print(e)
        server_check(k, now)
        return 1
    for x in errs:   # причина по каждой странице — в лог запуска
        print(f"  ошибка API: {x}")
    left = [u for u in targets if u not in done]
    if left:
        print(f"  не дошла очередь ({len(left)}, лимит приложения {api.usage}%): {', '.join(left)}")
    if not got:
        limited = any(LIMIT_RE.search(x.split(": ", 1)[-1]) for x in errs) or api.usage >= USAGE_STOP or not errs
        print("ни одной страницы не получено; " + ("; ".join(errs[:5]) or "лимит"))
        journal(0, "; ".join(errs[:2]) or f"лимит {api.usage}%")
        save("network", net, k)
        server_check(k, now)
        # лимит — не поломка: цифры прошлого часа и сервера остаются на сайте, следующий запуск через час.
        # Добор отдельных страниц — тоже не поломка: одна закрытая страница не должна краснить каждый пинок
        return 0 if limited or partial else 1
    net["apiBad"] = {"h": hour, "u": sorted(bad | new_bad)}

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
        if "media" in b:
            x["posts"] = [post(m) for m in b["media"].get("data", [])]
            x["postsAt"] = at
    g["at"] = at

    # почасовой график (network.hourly: 48 слотов с start, по часу): окно — до текущего часа, в него — замер API
    hr = net.get("hourly")
    if isinstance(hr, dict) and hr.get("start") and isinstance(hr.get("acc"), dict):
        n_slots = max((len(v.get("f") or []) for v in hr["acc"].values()), default=48) or 48
        start = datetime.fromisoformat(hr["start"]).replace(tzinfo=MSK)
        cur = now.replace(minute=0, second=0, microsecond=0)
        shift = int((cur - start).total_seconds() // 3600) - (n_slots - 1)
        if shift > 0:
            for v in hr["acc"].values():
                for fld, fill in (("f", None), ("p", 0)):
                    arr = list(v.get(fld) or [fill] * n_slots)
                    v[fld] = (arr + [fill] * shift)[-n_slots:] if shift < n_slots else [fill] * n_slots
            hr["start"] = (start + timedelta(hours=shift)).strftime("%Y-%m-%dT%H:00")
        start = datetime.fromisoformat(hr["start"]).replace(tzinfo=MSK)
        for u, b in got.items():
            v = hr["acc"].setdefault(u, {"f": [None] * n_slots, "p": [0] * n_slots})
            i = int((cur - start).total_seconds() // 3600)
            if 0 <= i < len(v["f"]) and b.get("followers_count") is not None:
                v["f"][i] = b["followers_count"]
            if "media" in b:   # посты по часам выхода — из тех же данных API
                for m in (b.get("media") or {}).get("data", []):
                    if m.get("timestamp"):
                        tj = datetime.strptime(m["timestamp"], "%Y-%m-%dT%H:%M:%S%z").astimezone(MSK).replace(minute=0, second=0)
                        j = int((tj - start).total_seconds() // 3600)
                        if 0 <= j < len(v["p"]) and v["p"][j] == 0:
                            v["p"][j] = 1

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
    journal(len(got), "; ".join(errs[:2]) + (f"; не дошла очередь {len(left)}" if left else ""))

    save("live", live, k)
    save("network", net, k)
    server_check(k, now)
    print(f"API: {len(got)}/{len(users)} страниц · с постами {sum('media' in b for b in got.values())} · запросов {api.calls}, "
          f"лимит {api.usage}% · выход {c}" + (f" · ошибки: {'; '.join(errs[:3])}" if errs else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
