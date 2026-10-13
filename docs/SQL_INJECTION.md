# Exercise 04 — Why prepared statements stop SQL injection

Two pages do the same job — look up users by username:

| | `public/vulnerable_search.php` ❌ | `public/search.php` ✅ |
|---|---|---|
| How the query is built | string concatenation | prepared statement with a bound parameter |
| Where the code lives | inline in the page | `UserRepository::searchByUsername()` |

## The vulnerable version

```php
$sql  = "SELECT id, username, email FROM users WHERE username = '" . $_GET['username'] . "'";
$rows = $pdo->query($sql)->fetchAll();
```

The input is pasted **into the SQL code**. The database receives one string
and has no way of knowing which part was written by the developer and which
part came from the visitor.

### Attack 1 — return every row

Input: `' OR '1'='1`

```sql
SELECT id, username, email FROM users WHERE username = '' OR '1'='1'
```

The first quote closes the string literal, `OR '1'='1'` is always true, and the
last quote of the payload pairs up with the quote the developer wrote. The
`WHERE` clause matches every row → all users and their email addresses leak.

### Attack 2 — read other columns/tables with UNION

Input: `' UNION SELECT id, username, password FROM users --`

```sql
SELECT id, username, email FROM users WHERE username = ''
UNION SELECT id, username, password FROM users --'
```

`--` comments out the developer's trailing quote. The page now prints the
**password hashes** in the "email" column. The same technique reads any
table (`sqlite_master` / `information_schema` reveal the rest of the schema).

Turning off error messages does not help: an attacker can still extract data
"blind" with true/false questions or timing — hiding errors is not a fix.

## The safe version

```php
$stmt = $pdo->prepare(
    "SELECT id, username, email FROM users
     WHERE LOWER(username) LIKE LOWER(:pattern) ESCAPE '!'
     ORDER BY username LIMIT :limit"
);
$stmt->bindValue(':pattern', $pattern, PDO::PARAM_STR);
$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
$stmt->execute();
```

### Why this cannot be injected

1. **Code and data travel separately.** `prepare()` sends the SQL text with a
   placeholder (`:pattern`) to the database, which parses and compiles it
   *before it has seen any user input*. The structure of the query is fixed at
   this point.
2. **The value is bound afterwards** (`bindValue()` / `execute()`). It is
   delivered as a typed value, never parsed as SQL. `' OR '1'='1` is just a
   10-character string the database compares against usernames — it matches
   nobody.
3. **No escaping to forget.** Manual escaping (`addslashes`, `quote()`) is
   fragile: one forgotten call, the wrong character set, or a numeric context
   without quotes (`WHERE id = $id`) is enough to break it. With placeholders
   there is nothing to remember.
4. **`PDO::ATTR_EMULATE_PREPARES => false`** (see `Database.php`) makes PDO use
   the database's native prepared statements on MySQL instead of emulating
   them by escaping on the client side. SQLite always prepares natively.

### Details that are easy to miss

- **LIKE wildcards are data too.** A bound parameter cannot change the query,
  but `%` and `_` still mean "anything" inside `LIKE`. Without escaping,
  searching for `%` would list every user. `searchByUsername()` escapes them
  (`ESCAPE '!'`).
- **Placeholders only work for values**, not for identifiers (table/column
  names) or keywords such as `ASC`/`DESC`. If those ever need to be dynamic,
  pick them from a hard-coded allow-list.
- **Defense in depth:** input validation (allow-listed username characters at
  registration), least-privilege database accounts, and logging of suspicious
  input (Exercise 07) — but the prepared statement is the actual fix.

## Try it

```text
http://localhost:8000/vulnerable_search.php?username=' OR '1'='1
http://localhost:8000/search.php?username=' OR '1'='1          → 0 results
```
