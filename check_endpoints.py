#!/usr/bin/env python3
"""
Проверка сетевого доступа к URL из endpoints.txt

Запуск на сервере:
  python3 check_endpoints.py endpoints.txt
  python3 check_endpoints.py endpoints.txt -w 100 -t 5 --insecure

Результат:
  reachable.txt    — доступные
  unreachable.txt  — недоступные
  results_all.csv  — полный отчёт
"""

from __future__ import annotations

import argparse
import csv
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass
class CheckResult:
    endpoint: str
    reachable: bool
    status: str
    http_code: str
    error: str
    elapsed_ms: int


def normalize_url(raw: str) -> Optional[str]:
    url = (raw or "").strip()
    if not url or url.startswith("#"):
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return url


def check_one(endpoint: str, timeout: float, insecure_ssl: bool) -> CheckResult:
    url = normalize_url(endpoint)
    started = time.monotonic()

    if not url:
        return CheckResult(
            endpoint=endpoint,
            reachable=False,
            status="invalid_url",
            http_code="",
            error="empty or invalid endpoint",
            elapsed_ms=0,
        )

    ctx = None
    if url.startswith("https://") and insecure_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "endpoint-reachability-check/1.0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            return CheckResult(
                endpoint=endpoint,
                reachable=True,
                status="ok",
                http_code=str(code),
                error="",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
    except HTTPError as e:
        # Любой HTTP-ответ = сеть есть
        return CheckResult(
            endpoint=endpoint,
            reachable=True,
            status="http_error",
            http_code=str(e.code),
            error=str(e.reason or e),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as e:
        elapsed = int((time.monotonic() - started) * 1000)
        err = str(e).strip() or type(e).__name__
        low = err.lower()

        if "certificate" in low or "ssl" in low:
            return CheckResult(
                endpoint=endpoint,
                reachable=True,
                status="ssl_error",
                http_code="",
                error=err,
                elapsed_ms=elapsed,
            )
        if "timed out" in low or "timeout" in low:
            status = "timeout"
        elif "name or service not known" in low or "nodename nor servname" in low:
            status = "dns_error"
        elif "connection refused" in low:
            status = "connection_refused"
        elif "network is unreachable" in low or "no route to host" in low:
            status = "network_unreachable"
        else:
            status = "error"

        return CheckResult(
            endpoint=endpoint,
            reachable=False,
            status=status,
            http_code="",
            error=err,
            elapsed_ms=elapsed,
        )


def load_endpoints(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    result = []
    seen = set()
    for line in lines:
        url = normalize_url(line)
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        result.append(url)
    return result


def write_lines(path: Path, urls: list[str]) -> None:
    path.write_text(("\n".join(urls) + "\n") if urls else "", encoding="utf-8")


def write_csv(path: Path, rows: list[CheckResult]) -> None:
    fields = ["endpoint", "reachable", "status", "http_code", "error", "elapsed_ms"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "endpoint": r.endpoint,
                    "reachable": "yes" if r.reachable else "no",
                    "status": r.status,
                    "http_code": r.http_code,
                    "error": r.error,
                    "elapsed_ms": r.elapsed_ms,
                }
            )


def main() -> int:
    p = argparse.ArgumentParser(description="Проверка сетевого доступа к URL из файла")
    p.add_argument(
        "endpoints_file",
        nargs="?",
        default="endpoints.txt",
        help="Файл со списком URL (по одному на строку), default: endpoints.txt",
    )
    p.add_argument("-w", "--workers", type=int, default=50)
    p.add_argument("-t", "--timeout", type=float, default=5.0)
    p.add_argument("--insecure", action="store_true", help="не проверять SSL")
    p.add_argument("-o", "--output-dir", default=".")
    args = p.parse_args()

    ep_path = Path(args.endpoints_file)
    if not ep_path.is_file():
        raise SystemExit(f"Файл не найден: {ep_path}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    endpoints = load_endpoints(ep_path)
    total = len(endpoints)
    if total == 0:
        raise SystemExit("В файле нет валидных http/https URL")

    print(f"Загружено URL: {total} | workers={args.workers} timeout={args.timeout}s")

    results: list[CheckResult] = []
    done = reachable_n = unreachable_n = 0
    t0 = time.monotonic()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(check_one, url, args.timeout, args.insecure): url
            for url in endpoints
        }
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            done += 1
            reachable_n += int(res.reachable)
            unreachable_n += int(not res.reachable)
            if done % 100 == 0 or done == total:
                rate = done / (time.monotonic() - t0)
                print(
                    f"  [{done}/{total}] ok={reachable_n} fail={unreachable_n} ({rate:.1f}/s)"
                )

    order = {url: i for i, url in enumerate(endpoints)}
    results.sort(key=lambda x: order.get(x.endpoint, 10**9))

    reachable = [r.endpoint for r in results if r.reachable]
    unreachable = [r.endpoint for r in results if not r.reachable]

    reachable_path = out_dir / "reachable.txt"
    unreachable_path = out_dir / "unreachable.txt"
    all_path = out_dir / "results_all.csv"

    write_lines(reachable_path, reachable)
    write_lines(unreachable_path, unreachable)
    write_csv(all_path, results)

    print()
    print("===== ИТОГО =====")
    print(f"Всего:       {total}")
    print(f"Доступны:    {reachable_n}  -> {reachable_path.resolve()}")
    print(f"Нет доступа: {unreachable_n}  -> {unreachable_path.resolve()}")
    print(f"Полный отчёт: {all_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
