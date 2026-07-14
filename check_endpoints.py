#!/usr/bin/env python3
"""
Проверка сетевого доступа к driver.endpoint из CSV мерчантов.

Использование:
  python3 check_endpoints.py paycom_merchants_for_apm.csv
  python3 check_endpoints.py paycom_merchants_for_apm.csv -w 100 -t 5

Результат:
  results_all.csv          — все проверки
  results_unreachable.csv  — только без сетевого доступа
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
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


# Доступ есть, если установили TCP/TLS и получили HTTP-ответ (даже 401/404/500).
# Нет доступа: timeout, DNS, connection refused, network unreachable и т.п.
OK_NETWORK_STATUSES = {
    "ok",
    "http_error",  # сервер ответил кодом ошибки = сеть есть
}


@dataclass
class CheckResult:
    _id: str
    name: str
    organization: str
    driver_name: str
    endpoint: str
    reachable: bool
    status: str
    http_code: str
    error: str
    elapsed_ms: int


def normalize_url(raw: str) -> Optional[str]:
    url = (raw or "").strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return url


def check_one(
    row: dict,
    timeout: float,
    insecure_ssl: bool,
) -> CheckResult:
    endpoint = (row.get("driver.endpoint") or "").strip()
    url = normalize_url(endpoint)
    started = time.monotonic()

    base = dict(
        _id=row.get("_id", ""),
        name=row.get("name", ""),
        organization=row.get("organization", ""),
        driver_name=row.get("driver.name", ""),
        endpoint=endpoint,
    )

    if not url:
        return CheckResult(
            **base,
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
            elapsed = int((time.monotonic() - started) * 1000)
            return CheckResult(
                **base,
                reachable=True,
                status="ok",
                http_code=str(code),
                error="",
                elapsed_ms=elapsed,
            )
    except HTTPError as e:
        # HTTP-ответ получен — сеть до хоста есть
        elapsed = int((time.monotonic() - started) * 1000)
        return CheckResult(
            **base,
            reachable=True,
            status="http_error",
            http_code=str(e.code),
            error=str(e.reason or e),
            elapsed_ms=elapsed,
        )
    except Exception as e:
        elapsed = int((time.monotonic() - started) * 1000)
        err = str(e).strip() or type(e).__name__
        # Частые случаи отсутствия доступа
        low = err.lower()
        if "timed out" in low or "timeout" in low:
            status = "timeout"
        elif "name or service not known" in low or "nodename nor servname" in low:
            status = "dns_error"
        elif "connection refused" in low:
            status = "connection_refused"
        elif "network is unreachable" in low or "no route to host" in low:
            status = "network_unreachable"
        elif "certificate" in low or "ssl" in low:
            # SSL-проблема: TCP уже установили, но считаем осторожно.
            # По умолчанию помечаем как reachable=False только если это чистый сетевой сбой.
            # SSL handshake failure обычно значит хост доступен.
            status = "ssl_error"
            return CheckResult(
                **base,
                reachable=True,
                status=status,
                http_code="",
                error=err,
                elapsed_ms=elapsed,
            )
        else:
            status = "error"

        return CheckResult(
            **base,
            reachable=False,
            status=status,
            http_code="",
            error=err,
            elapsed_ms=elapsed,
        )


def load_rows(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "driver.endpoint" not in reader.fieldnames:
            raise SystemExit(
                f"В CSV нет колонки driver.endpoint. Найдено: {reader.fieldnames}"
            )
        return list(reader)


def write_csv(path: Path, rows: list[CheckResult]) -> None:
    fields = [
        "_id",
        "name",
        "organization",
        "driver_name",
        "endpoint",
        "reachable",
        "status",
        "http_code",
        "error",
        "elapsed_ms",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow(
                {
                    "_id": r._id,
                    "name": r.name,
                    "organization": r.organization,
                    "driver_name": r.driver_name,
                    "endpoint": r.endpoint,
                    "reachable": "yes" if r.reachable else "no",
                    "status": r.status,
                    "http_code": r.http_code,
                    "error": r.error,
                    "elapsed_ms": r.elapsed_ms,
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверка сетевого доступа к HTTP(S) endpoint из CSV"
    )
    parser.add_argument("csv_file", help="Путь к CSV (колонка driver.endpoint)")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Число параллельных проверок (default: 50)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Таймаут на один URL в секундах (default: 5)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Не проверять SSL-сертификаты (полезно для внутренних https)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Куда сохранить результаты (default: текущая папка)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv_file)
    if not csv_path.is_file():
        raise SystemExit(f"Файл не найден: {csv_path}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_rows(csv_path)
    total = len(rows)
    print(f"Загружено строк: {total}")
    print(f"Workers={args.workers}, timeout={args.timeout}s, insecure_ssl={args.insecure}")
    print("Старт проверки...")

    results: list[CheckResult] = []
    done = 0
    reachable_n = 0
    unreachable_n = 0
    t0 = time.monotonic()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(check_one, row, args.timeout, args.insecure) for row in rows
        ]
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            if res.reachable:
                reachable_n += 1
            else:
                unreachable_n += 1
            if done % 100 == 0 or done == total:
                elapsed = time.monotonic() - t0
                rate = done / elapsed if elapsed else 0
                print(
                    f"  [{done}/{total}] ok={reachable_n} fail={unreachable_n} "
                    f"({rate:.1f}/s)"
                )

    # стабильный порядок как в исходном файле
    order = {(r.get("_id"), (r.get("driver.endpoint") or "").strip()): i for i, r in enumerate(rows)}
    results.sort(
        key=lambda x: order.get((x._id, x.endpoint), 10**9)
    )

    all_path = out_dir / "results_all.csv"
    bad_path = out_dir / "results_unreachable.csv"
    write_csv(all_path, results)
    write_csv(bad_path, [r for r in results if not r.reachable])

    elapsed = time.monotonic() - t0
    print()
    print("===== ИТОГО =====")
    print(f"Всего:          {total}")
    print(f"Доступны:       {reachable_n}")
    print(f"Нет доступа:    {unreachable_n}")
    print(f"Время:          {elapsed:.1f}s")
    print(f"Все результаты: {all_path.resolve()}")
    print(f"Без доступа:    {bad_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
