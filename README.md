# Endpoint reachability checker

## Файлы для копирования на сервер

1. `endpoints.txt` — уникальные HTTP(S) URL (один на строку)
2. `check_endpoints.py` — скрипт проверки

## Запуск

```bash
python3 check_endpoints.py endpoints.txt -w 100 -t 5 --insecure
```

## Результат

| Файл | Содержимое |
|------|------------|
| `reachable.txt` | URL с сетевым доступом |
| `unreachable.txt` | URL без сетевого доступа |
| `results_all.csv` | полный отчёт (статус, код, ошибка) |

Доступ **есть**: любой HTTP-ответ (в т.ч. 401/404/500) или SSL-ошибка после TCP.  
Доступа **нет**: timeout / DNS / connection refused / network unreachable.
