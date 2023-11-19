# Pure Python Async MySQL/MariaDB Test Driver

Prototype Python MySQL/MariaDB Async Driver for testing server connections

```
usage: driver.py [-h] --host HOST [--port PORT] --username USERNAME [--password PASSWORD] [--database DATABASE] [--query QUERY] [--compressed]

options:
  -h, --help           show this help message and exit
  --host HOST          Database Host/IP
  --port PORT          Port to connect to (default: 3306)
  --username USERNAME  Database user
  --password PASSWORD  Database user password (prompted if not set)
  --database DATABASE  Database to connect to (optional)
  --query QUERY        Query to test (default: SELECT 1)
  --compressed         Use compression (default: False)
```

Usage Example:

```
python driver.py --username root --host 127.0.0.1 --database performance_schema --query 'SELECT 1,CURRENT_TIMESTAMP() AS time'
```
