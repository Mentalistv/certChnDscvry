import sqlite3
import sys
import os
import re

def parse_line(line):
    # Example line: KA Bob Alice -> KB delta [1]
    # or: KA Bob Alice -> KB delta

    # Match using regex
    match = re.match(r"(\w+)\s+(.+?)\s*->\s*(.+?)(?:\s+\[(\d)\])?$", line.strip())
    if not match:
        return None

    issuer, local_name, subject, delegation = match.groups()
    local_name = issuer + " " + local_name
    delegation_bit = int(delegation) if delegation is not None else 0
    cert_type = "AUTH" if delegation is not None else "NAME"

    return issuer, local_name.strip(), subject.strip(), cert_type, delegation_bit

def main():
    if len(sys.argv) != 2:
        print("Usage: python parse_certs_to_sqlite.py input.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    db_file = os.path.splitext(input_file)[0] + ".db"

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    issuer_tables = {}

    with open(input_file, 'r') as file:
        for line in file:
            if not line.strip():
                continue

            parsed = parse_line(line)
            if not parsed:
                print(f"Skipping invalid line: {line.strip()}")
                continue

            issuer, local_name, subject, cert_type, delegation_bit = parsed

            if issuer not in issuer_tables:
                # Create table for this issuer
                table_name = issuer
                issuer_tables[issuer] = table_name
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS [{table_name}] (
                        sno INTEGER PRIMARY KEY AUTOINCREMENT,
                        local_name TEXT,
                        subject TEXT,
                        type TEXT,
                        delegation_bit INTEGER
                    );
                """)

            # Insert into issuer's table
            cursor.execute(f"""
                INSERT INTO [{issuer_tables[issuer]}]
                (local_name, subject, type, delegation_bit)
                VALUES (?, ?, ?, ?);
            """, (local_name, subject, cert_type, delegation_bit))

    conn.commit()
    conn.close()
    print(f"Database created: {db_file}")

if __name__ == "__main__":
    main()
