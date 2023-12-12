from pathlib import Path
from zipfile import ZipFile

with ZipFile('mysql.driver', 'w') as f:
    root = Path('protocol')
    tests = Path('protocol') / 'test'
    for entry in root.rglob('*'):
        if not entry.is_relative_to(tests) and '__pycache__' not in entry.parts:
            f.write(entry, entry)
    f.write('driver.py', '__main__.py')
