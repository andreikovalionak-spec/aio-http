import os
from datetime import datetime, timezone

import asyncpg
import jwt
from aiohttp import web
from werkzeug.security import check_password_hash, generate_password_hash

SECRET = "change-me-in-production"
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/ads")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS ads (
    id SERIAL PRIMARY KEY,
    title VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    owner_id INTEGER NOT NULL REFERENCES users(id)
);
"""


def error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


def get_token(request: web.Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header.split(" ", 1)[1]
    return None


def auth_required(fn):
    @web.middleware
    async def wrapper(request):
        token = get_token(request)
        if not token:
            return error(401, "требуется авторизация")
        try:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return error(401, "неверный токен")
        async with request.app["pool"].acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, email FROM users WHERE id = $1", payload["user_id"]
            )
        if user is None:
            return error(401, "пользователь не найден")
        request["current_user"] = user
        return await fn(request)
    return wrapper


def owner_required(fn):
    @auth_required
    async def wrapper(request):
        ad_id = int(request.match_info["ad_id"])
        async with request.app["pool"].acquire() as conn:
            ad = await conn.fetchrow("SELECT * FROM ads WHERE id = $1", ad_id)
        if ad is None:
            return error(404, "объявление не найдено")
        if ad["owner_id"] != request["current_user"]["id"]:
            return error(403, "нет прав на это объявление")
        request["ad"] = ad
        return await fn(request)
    return wrapper


async def register(request: web.Request) -> web.Response:
    data = await request.json() if request.can_read_body else {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return error(400, "нужны email и password")
    pool = request.app["pool"]
    async with pool.acquire() as conn:
        if await conn.fetchval("SELECT 1 FROM users WHERE email = $1", email):
            return error(409, "email уже занят")
        row = await conn.fetchrow(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) "
            "RETURNING id, email",
            email, generate_password_hash(password),
        )
    return web.json_response({"id": row["id"], "email": row["email"]}, status=201)


async def login(request: web.Request) -> web.Response:
    data = await request.json() if request.can_read_body else {}
    async with request.app["pool"].acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, password_hash FROM users WHERE email = $1", data.get("email")
        )
    if user is None or not check_password_hash(user["password_hash"], data.get("password", "")):
        return error(401, "неверный email или пароль")
    token = jwt.encode({"user_id": user["id"]}, SECRET, algorithm="HS256")
    return web.json_response({"token": token})


@auth_required
async def create_ad(request: web.Request) -> web.Response:
    data = await request.json() if request.can_read_body else {}
    title, description = data.get("title"), data.get("description")
    if not title or not description:
        return error(400, "нужны title и description")
    async with request.app["pool"].acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO ads (title, description, owner_id) VALUES ($1, $2, $3) "
            "RETURNING id, title, description, created_at, owner_id",
            title, description, request["current_user"]["id"],
        )
    return web.json_response(ad_to_dict(row, request["current_user"]["email"]), status=201)


def ad_to_dict(ad, owner_email: str) -> dict:
    return {
        "id": ad["id"],
        "title": ad["title"],
        "description": ad["description"],
        "created_at": ad["created_at"].isoformat(),
        "owner_id": ad["owner_id"],
        "owner_email": owner_email,
    }


async def get_ad(request: web.Request) -> web.Response:
    ad_id = int(request.match_info["ad_id"])
    async with request.app["pool"].acquire() as conn:
        row = await conn.fetchrow(
            "SELECT a.*, u.email AS owner_email FROM ads a "
            "JOIN users u ON u.id = a.owner_id WHERE a.id = $1",
            ad_id,
        )
    if row is None:
        return error(404, "объявление не найдено")
    return web.json_response(ad_to_dict(row, row["owner_email"]))


@owner_required
async def update_ad(request: web.Request) -> web.Response:
    data = await request.json() if request.can_read_body else {}
    ad = request["ad"]
    title = data.get("title", ad["title"])
    description = data.get("description", ad["description"])
    async with request.app["pool"].acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE ads SET title = $1, description = $2 WHERE id = $3 "
            "RETURNING id, title, description, created_at, owner_id",
            title, description, ad["id"],
        )
    return web.json_response(ad_to_dict(row, request["current_user"]["email"]))


@owner_required
async def delete_ad(request: web.Request) -> web.Response:
    async with request.app["pool"].acquire() as conn:
        await conn.execute("DELETE FROM ads WHERE id = $1", request["ad"]["id"])
    return web.json_response({"status": "deleted"})


async def list_ads(request: web.Request) -> web.Response:
    async with request.app["pool"].acquire() as conn:
        rows = await conn.fetch(
            "SELECT a.*, u.email AS owner_email FROM ads a "
            "JOIN users u ON u.id = a.owner_id ORDER BY a.created_at DESC"
        )
    return web.json_response([ad_to_dict(r, r["owner_email"]) for r in rows])


async def on_startup(app: web.Application) -> None:
    app["pool"] = await asyncpg.create_pool(DATABASE_URL)
    async with app["pool"].acquire() as conn:
        await conn.execute(SCHEMA)


async def on_cleanup(app: web.Application) -> None:
    await app["pool"].close()


def create_app() -> web.Application:
    app = web.Application()
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_post("/register", register)
    app.router.add_post("/login", login)
    app.router.add_post("/ads", create_ad)
    app.router.add_get("/ads", list_ads)
    app.router.add_get("/ads/{ad_id}", get_ad)
    app.router.add_patch("/ads/{ad_id}", update_ad)
    app.router.add_delete("/ads/{ad_id}", delete_ad)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=5000)

