# auth-playground

A playground for auth concepts.

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
