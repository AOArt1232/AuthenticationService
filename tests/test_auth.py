import pytest

GOOD = "Str0ng#Pass"
EMAIL = "tonya@example.com"


async def register(client, email=EMAIL, password=GOOD):
    return await client.post("/auth/register", json={"email": email, "password": password})


async def login(client, email=EMAIL, password=GOOD):
    r = await client.post("/auth/login", json={"email": email, "password": password})
    return r


async def test_register_ok(client):
    r = await register(client)
    assert r.status_code == 201
    assert r.json()["email"] == EMAIL


async def test_register_duplicate(client):
    await register(client)
    r = await register(client, email=EMAIL.upper())
    assert r.status_code == 409


@pytest.mark.parametrize("email", ["nope", "a@", "@b.com", "a b@c.com"])
async def test_register_bad_email(client, email):
    assert (await register(client, email=email)).status_code == 422


@pytest.mark.parametrize(
    "password",
    [
        "Sh0rt#",                     # too short
        "Aa1#" * 7,                   # too long (28)
        "nouppercase1#",
        "NOLOWERCASE1#",
        "NoDigits###",
        "NoSpecial123",
        "Has@Symbol1",
        'Has"Quote1#',
        "Has'Quote1#",
        "Has<Tag1#",
        "Has>Tag1#",
        "Has Space1#",
    ],
)
async def test_register_bad_password(client, password):
    assert (await register(client, password=password)).status_code == 422


@pytest.mark.parametrize("password", ["Abcdef1!", "Aa1!" * 6])
async def test_password_length_bounds(client, password):
    assert (await register(client, password=password)).status_code == 201


async def test_login_and_me(client):
    await register(client)
    r = await login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


async def test_login_wrong_password(client):
    await register(client)
    assert (await login(client, password="Wr0ng#Pass")).status_code == 401


async def test_login_unknown_user(client):
    assert (await login(client)).status_code == 401


async def test_login_email_case_insensitive(client):
    await register(client)
    assert (await login(client, email=EMAIL.upper())).status_code == 200



async def test_login_timing_same_for_unknown_email(client, monkeypatch):
    # Both failure paths must run the password hash exactly once.
    import app.routes as routes

    calls = []
    real = routes.verify_password

    async def counting(password, stored):
        calls.append(stored)
        return await real(password, stored)

    monkeypatch.setattr(routes, "verify_password", counting)
    await register(client)
    assert (await login(client, password="Wr0ng#Pass")).status_code == 401
    assert (await login(client, email="ghost@example.com")).status_code == 401
    assert len(calls) == 2


# --- Tests that need the JWT token ---

def auth(token):
    return {"Authorization": f"Bearer {token}"}


async def get_token(client):
    await register(client)
    return (await login(client)).json()["access_token"]


async def test_me_with_token(client):
    token = await get_token(client)
    r = await client.get("/auth/me", headers=auth(token))
    assert r.status_code == 200
    assert r.json()["email"] == EMAIL


async def test_me_without_token(client):
    r = await client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["detail"] == "Not authenticated"


async def test_me_with_garbage_token(client):
    assert (await client.get("/auth/me", headers=auth("not-a-jwt"))).status_code == 401


async def test_me_with_tampered_token(client):
    # Change the payload to pretend to be user 999; the signature no longer matches.
    import base64
    import json

    token = await get_token(client)
    header, payload, signature = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    data["sub"] = "999"
    fake = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    r = await client.get("/auth/me", headers=auth(f"{header}.{fake}.{signature}"))
    assert r.status_code == 401


async def test_me_with_token_signed_by_wrong_secret(client):
    import jwt

    await get_token(client)
    forged = jwt.encode({"sub": "1"}, "someone-elses-secret-0123456789abcdef", algorithm="HS256")
    assert (await client.get("/auth/me", headers=auth(forged))).status_code == 401


async def test_me_with_expired_token(client, monkeypatch):
    from app.config import settings

    await register(client)
    monkeypatch.setattr(settings, "access_token_minutes", -1)  # token born already expired
    token = (await login(client)).json()["access_token"]
    r = await client.get("/auth/me", headers=auth(token))
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token"


# --- Unknown users and JWT content ---

def make_token(**claims):
    import time

    import jwt

    from app.config import settings

    now = int(time.time())
    data = {"sub": "1", "iat": now, "exp": now + 600, "jti": "a" * 32, "ver": 0} | claims
    data = {k: v for k, v in data.items() if v is not None}
    return jwt.encode(data, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def test_me_unknown_user_same_error_as_bad_token(client):
    # Correctly signed token for a user id that doesn't exist.
    await get_token(client)
    r = await client.get("/auth/me", headers=auth(make_token(sub="999")))
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token"


async def test_me_correctly_signed_token_works(client):
    await get_token(client)
    r = await client.get("/auth/me", headers=auth(make_token(sub="1")))
    assert r.status_code == 200


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": None},             # missing sub
        {"jti": None},             # missing jti
        {"ver": None},             # missing ver
        {"jti": "short"},          # jti in the wrong format
        {"ver": -1},
        {"ver": "zero"},
        {"exp": None},             # missing exp
        {"iat": None},             # missing iat
        {"sub": "abc"},            # sub not a number
        {"sub": "0"},              # not a valid id
        {"sub": "-1"},
        {"sub": ""},
        {"sub": "1", "admin": True},  # unexpected extra claim
    ],
)
async def test_me_rejects_bad_token_content(client, claims):
    await get_token(client)
    r = await client.get("/auth/me", headers=auth(make_token(**claims)))
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token"


async def test_me_rejects_unsigned_token(client):
    import jwt

    await get_token(client)
    token = jwt.encode({"sub": "1", "iat": 0, "exp": 9999999999}, None, algorithm="none")
    assert (await client.get("/auth/me", headers=auth(token))).status_code == 401


async def test_me_rejects_wrong_auth_scheme(client):
    token = await get_token(client)
    r = await client.get("/auth/me", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 401


# --- Invalid input data ---

@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
@pytest.mark.parametrize(
    "body",
    [
        {},
        {"email": EMAIL},
        {"password": GOOD},
        {"email": None, "password": GOOD},
        {"email": EMAIL, "password": None},
        {"email": 123, "password": GOOD},
        {"email": EMAIL, "password": 12345678},
        {"email": ["a@b.com"], "password": GOOD},
        {"email": EMAIL, "password": GOOD, "is_admin": True},  # unknown field
    ],
)
async def test_invalid_body(client, path, body):
    assert (await client.post(path, json=body)).status_code == 422


@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
async def test_not_json(client, path):
    r = await client.post(path, content="email=a&password=b",
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 422
    r = await client.post(path, content="{broken json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422


async def test_login_empty_and_huge_password(client):
    await register(client)
    assert (await login(client, password="")).status_code == 422
    assert (await login(client, password="A1#a" * 100)).status_code == 422


async def test_errors_never_echo_password(client):
    r = await register(client, password="Has@Symbol1")
    assert r.status_code == 422
    assert "Has@Symbol1" not in r.text


# --- Logout ---

async def test_logout_revokes_token(client):
    token = await get_token(client)
    r = await client.post("/auth/logout", headers=auth(token))
    assert r.status_code == 200
    assert r.json()["detail"] == "Logged out"
    assert (await client.get("/auth/me", headers=auth(token))).status_code == 401
    assert (await client.post("/auth/logout", headers=auth(token))).status_code == 401


async def test_logout_only_ends_that_session(client):
    token1 = await get_token(client)
    token2 = (await login(client)).json()["access_token"]  # e.g. a second device
    assert token1 != token2
    await client.post("/auth/logout", headers=auth(token1))
    assert (await client.get("/auth/me", headers=auth(token2))).status_code == 200


async def test_logout_needs_token(client):
    assert (await client.post("/auth/logout")).status_code == 401
    assert (await client.post("/auth/logout", headers=auth("garbage"))).status_code == 401


async def test_login_again_after_logout(client):
    token = await get_token(client)
    await client.post("/auth/logout", headers=auth(token))
    new = (await login(client)).json()["access_token"]
    assert (await client.get("/auth/me", headers=auth(new))).status_code == 200


# --- Password change ---

NEW = "N3w$Secret"


async def change(client, token, old=GOOD, new=NEW):
    return await client.post(
        "/auth/change-password",
        json={"old_password": old, "new_password": new},
        headers=auth(token),
    )


async def test_change_password(client):
    token = await get_token(client)
    r = await change(client, token)
    assert r.status_code == 200
    assert (await login(client)).status_code == 401           # old password stops working
    assert (await login(client, password=NEW)).status_code == 200


async def test_change_password_logs_out_all_devices(client):
    token1 = await get_token(client)
    token2 = (await login(client)).json()["access_token"]
    await change(client, token1)
    assert (await client.get("/auth/me", headers=auth(token1))).status_code == 401
    assert (await client.get("/auth/me", headers=auth(token2))).status_code == 401
    fresh = (await login(client, password=NEW)).json()["access_token"]
    assert (await client.get("/auth/me", headers=auth(fresh))).status_code == 200


async def test_change_password_wrong_old(client):
    token = await get_token(client)
    r = await change(client, token, old="Wr0ng#Pass")
    assert r.status_code == 400
    assert (await login(client)).status_code == 200          # nothing changed


async def test_change_password_same_as_old(client):
    token = await get_token(client)
    assert (await change(client, token, new=GOOD)).status_code == 400


@pytest.mark.parametrize("new", ["weak", "NoDigits###", "Has@Symbol1", "Aa1!" * 7])
async def test_change_password_new_must_follow_rules(client, new):
    token = await get_token(client)
    assert (await change(client, token, new=new)).status_code == 422


async def test_change_password_needs_token(client):
    await register(client)
    r = await client.post("/auth/change-password", json={"old_password": GOOD, "new_password": NEW})
    assert r.status_code == 401
    assert (await login(client)).status_code == 200


async def test_change_password_with_logged_out_token(client):
    token = await get_token(client)
    await client.post("/auth/logout", headers=auth(token))
    assert (await change(client, token)).status_code == 401


@pytest.mark.parametrize(
    "body",
    [{}, {"old_password": GOOD}, {"new_password": NEW},
     {"old_password": GOOD, "new_password": NEW, "extra": 1},
     {"old_password": None, "new_password": NEW}],
)
async def test_change_password_invalid_body(client, body):
    token = await get_token(client)
    r = await client.post("/auth/change-password", json=body, headers=auth(token))
    assert r.status_code == 422
