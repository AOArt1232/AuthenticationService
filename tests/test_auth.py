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

