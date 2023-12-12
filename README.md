# Pure Python Async MySQL/MariaDB Test Driver

Prototype Python MySQL/MariaDB Async Driver for testing server connections

**Security Note:** _Prepared statements of any kind are not yet supported!_

Please do not use this in production as it is easy to create sql injection vulnerabilities
without proper escaping when using non-literal queries.

Currently only the `native_password` authentication is supported.

## Status

The help message for the driver script shows the library status pretty well:

```
usage: driver.py [-h] --host HOST [--port PORT] --username USERNAME [--password PASSWORD] [--database DATABASE] [--query QUERY] [--compressed] [--ssl] [--ssl-no-verify]

options:
  -h, --help           show this help message and exit
  --host HOST          Database Host/IP
  --port PORT          Port to connect to (default: 3306)
  --username USERNAME  Database user
  --password PASSWORD  Database user password (prompted if not set)
  --database DATABASE  Database to connect to (optional)
  --query QUERY        Query to test (default: SELECT 1)
  --compressed         Use compression (default: False)
  --ssl                Use SSL
  --ssl-no-verify      Do not verify certs
```

Usage Example:

```
python driver.py --username root --host 127.0.0.1 --database performance_schema --query 'SELECT 1,CURRENT_TIMESTAMP() AS time'
```

See the [generate_encoding.py](generate_encodings.py) for usage in scripts.

You can generate a single zipfile to run the driver standalone:

```
python generate_singlefile.py
```

Then:

```
python mysql.driver -h
```

This will later be added as a release.
