# auth-playground

A playground for auth concepts.

## Architecture

```
+-------------+          redirect           +----------------+
|  Client     | --------------------------> |  Service       |
|  (curl)     |                             |  Provider      |
|             | <---- redirect to IdP ----  |  (RP)          |
+-------------+                             +--------+-------+
                                                    |
                                                    | /authorize
                                                    v
                                             +------+-------+
                                             | Identity     |
                                             | Provider     |
                                             | (Authorization|
                                             |  Server)     |
                                             +------+-------+
                                                    |
                                                    | code
                                                    v
                                             +------+-------+
                                             |  /callback   |
                                             | Service      |
                                             | Provider     |
                                             +------+-------+
                                                    |
                                                    | token exchange
                                                    v
                                             +------+-------+
                                             | /token       |
                                             | IdP          |
                                             +--------------+
```

## TODO
- Fix the warning about not using a production WSGI server.
- Move oidc_sim.py into src/ and break it apart into individual files.

## One-time

```
uv venv
```

## Activating virtual env

```
source .venv/bin/activate
```

## Triggering e2e flow

```
curl -L http://localhost:8000/ | jq
```
