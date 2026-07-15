# Endpoint lists

## Основные файлы

| Файл | Что внутри |
|------|------------|
| `endpoints.txt` | 4133 уникальных URL, по одному на строку (для `check_endpoints.py`) |
| `endpoints_sorted.csv` | все 6982 строки мерчантов, **отсортированы для фильтрации** |
| `endpoints_unique_sorted.csv` | 4133 уникальных endpoint, тот же порядок |
| `check_endpoints.py` | проверка сетевого доступа |

## Порядок сортировки в `*_sorted.csv`

1. **host_type** — `private_ip` → `public_ip` → `domain`
2. **host_group** — подсеть `/24` для IP, apex-домен для DNS
3. **host** → **port** → **path/endpoint**
4. **organization** → **name**

Доп. колонки для фильтра в Excel: `host_type`, `host_group`, `host`, `port`, `scheme`, `path`.

## Проверка доступа

```bash
python3 check_endpoints.py endpoints.txt -w 5 -t 5 --insecure
```

Результат: `reachable.txt`, `unreachable.txt`, `results_all.csv`.
