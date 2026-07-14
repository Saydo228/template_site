# Endpoint reachability checker

Скрипт `check_endpoints.py` проверяет с хоста, где запущен, есть ли **сетевой доступ** до URL из колонки `driver.endpoint` CSV.

## Запуск на сервере

```bash
# зависимости не нужны — только Python 3.8+
python3 check_endpoints.py paycom_merchants_for_apm.csv

# быстрее / для внутренних https без валидного сертификата
python3 check_endpoints.py paycom_merchants_for_apm.csv -w 100 -t 5 --insecure
```

## Результат

- `results_all.csv` — все проверки
- `results_unreachable.csv` — только URL **без** сетевого доступа

Считается что доступ **есть**, если получен любой HTTP-ответ (включая 401/403/404/500) или ошибка SSL после установки соединения.  
Считается что доступа **нет**: timeout, DNS error, connection refused, network unreachable.
