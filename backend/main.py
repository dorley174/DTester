from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("CONTEST_DB", str(BASE_DIR / "contest.db")))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "")
TEACHER_INVITE = os.getenv("TEACHER_INVITE", "")
ALLOW_UNSAFE_RUNNER = os.getenv("ALLOW_UNSAFE_RUNNER", "0") == "1"
PYTHON_BIN = os.getenv("CONTEST_PYTHON", shutil.which("python") or shutil.which("python3") or "python")
CPP_BIN = os.getenv("CONTEST_CPP", shutil.which("g++") or "")

app = FastAPI(title="AlgoArena API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          salt TEXT NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('teacher','student')), created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, statement TEXT NOT NULL, examples TEXT NOT NULL, tests TEXT NOT NULL,
          time_limit REAL NOT NULL DEFAULT 2, memory_mb INTEGER NOT NULL DEFAULT 128,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contests (
          id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, invite_code TEXT UNIQUE NOT NULL, task_ids TEXT NOT NULL,
          duration_minutes INTEGER NOT NULL DEFAULT 60, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS participants (
          contest_id INTEGER NOT NULL REFERENCES contests(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          joined_at INTEGER NOT NULL, PRIMARY KEY(contest_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          contest_id INTEGER REFERENCES contests(id) ON DELETE CASCADE,
          language TEXT NOT NULL, source TEXT NOT NULL, verdict TEXT NOT NULL,
          passed INTEGER NOT NULL, total INTEGER NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_submissions_contest ON submissions(contest_id,user_id,task_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner_id);
        """)


init_db()


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240_000).hex()


def token_for(uid: int, role: str) -> str:
    if not TOKEN_SECRET:
        raise HTTPException(500, "Сервер не настроен: задай TOKEN_SECRET в переменных окружения")
    payload = f"{uid}:{role}:{int(time.time()) + 7 * 86400}:{secrets.token_hex(8)}"
    sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + ":" + sig


def current_user(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Сначала войди в аккаунт")
    try:
        parts = authorization[7:].split(":")
        payload, sig = ":".join(parts[:-1]), parts[-1]
        expected = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        uid, role, expiry = int(parts[0]), parts[1], int(parts[2])
        if not TOKEN_SECRET or not hmac.compare_digest(sig, expected) or expiry < int(time.time()):
            raise ValueError()
        with connect() as c:
            row = c.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()
        if not row or row["role"] != role:
            raise ValueError()
        return dict(row)
    except (ValueError, IndexError, TypeError):
        raise HTTPException(401, "Сессия недействительна — войди заново")


def require_teacher(user: dict):
    if user["role"] != "teacher":
        raise HTTPException(403, "Это действие доступно только учителю")


class AuthIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: str = "student"
    teacher_invite: str = ""


class Example(BaseModel):
    input: str = Field(max_length=10000)
    output: str = Field(max_length=10000)


class TestCase(BaseModel):
    input: str = Field(max_length=50000)
    output: str = Field(max_length=50000)


class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=12000)
    examples: list[Example] = Field(default_factory=list, max_length=20)
    tests: list[TestCase] = Field(min_length=1, max_length=100)
    time_limit: float = Field(default=2.0, ge=0.2, le=10)
    memory_mb: int = Field(default=128, ge=32, le=512)


class ContestIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    task_ids: list[int] = Field(min_length=1, max_length=50)
    duration_minutes: int = Field(default=60, ge=5, le=600)

    @field_validator("task_ids")
    @classmethod
    def unique_task_ids(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("В контесте не должно быть повторяющихся задач")
        return value


class SubmitIn(BaseModel):
    task_id: int
    contest_code: Optional[str] = Field(default=None, max_length=40)
    language: str
    source: str = Field(min_length=1, max_length=50000)


@app.get("/api/health")
def health():
    return {"ok": True, "database": "sqlite", "runner_enabled": ALLOW_UNSAFE_RUNNER, "runner_mode": "local-unsandboxed" if ALLOW_UNSAFE_RUNNER else "disabled", "cpp_compiler": bool(CPP_BIN), "python": PYTHON_BIN}


@app.post("/api/register")
def register(data: AuthIn):
    if data.role not in ("teacher", "student"):
        raise HTTPException(400, "Неизвестная роль")
    if data.role == "teacher" and (not TEACHER_INVITE or not hmac.compare_digest(data.teacher_invite, TEACHER_INVITE)):
        raise HTTPException(403, "Неверный код регистрации учителя. Его задаёт владелец сервера.")
    salt = secrets.token_hex(16)
    now = int(time.time())
    try:
        with connect() as c:
            cur = c.execute("INSERT INTO users(username,salt,password_hash,role,created_at) VALUES(?,?,?,?,?)", (data.username, salt, password_hash(data.password, salt), data.role, now))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Это имя пользователя уже занято")
    return {"token": token_for(uid, data.role), "user": {"id": uid, "username": data.username, "role": data.role}}


@app.post("/api/login")
def login(data: AuthIn):
    with connect() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (data.username,)).fetchone()
    if not user or not hmac.compare_digest(password_hash(data.password, user["salt"]), user["password_hash"]):
        raise HTTPException(401, "Неверное имя пользователя или пароль")
    return {"token": token_for(user["id"], user["role"]), "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}


@app.get("/api/me")
def me(authorization: Optional[str] = Header(None)):
    return current_user(authorization)


def task_public(row):
    return {"id": row["id"], "title": row["title"], "statement": row["statement"], "examples": json.loads(row["examples"]), "time_limit": row["time_limit"], "memory_mb": row["memory_mb"], "created_at": row["created_at"], "updated_at": row["updated_at"]}


@app.get("/api/tasks")
def list_tasks(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM tasks WHERE owner_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return [task_public(r) for r in rows]


@app.get("/api/tasks/{task_id}")
def get_task(task_id: int, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        row = c.execute("SELECT * FROM tasks WHERE id=? AND owner_id=?", (task_id, user["id"])).fetchone()
    if not row: raise HTTPException(404, "Задача не найдена")
    result = task_public(row)
    result["tests"] = json.loads(row["tests"])
    return result


@app.post("/api/tasks")
def create_task(data: TaskIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    now = int(time.time())
    with connect() as c:
        cur = c.execute("INSERT INTO tasks(owner_id,title,statement,examples,tests,time_limit,memory_mb,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (user["id"], data.title.strip(), data.statement.strip(), json.dumps([x.model_dump() for x in data.examples], ensure_ascii=False), json.dumps([x.model_dump() for x in data.tests], ensure_ascii=False), data.time_limit, data.memory_mb, now, now))
    return {"id": cur.lastrowid, "title": data.title.strip()}


@app.put("/api/tasks/{task_id}")
def update_task(task_id: int, data: TaskIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        row = c.execute("SELECT id FROM tasks WHERE id=? AND owner_id=?", (task_id, user["id"])).fetchone()
        if not row: raise HTTPException(404, "Задача не найдена")
        c.execute("UPDATE tasks SET title=?,statement=?,examples=?,tests=?,time_limit=?,memory_mb=?,updated_at=? WHERE id=?", (data.title.strip(), data.statement.strip(), json.dumps([x.model_dump() for x in data.examples], ensure_ascii=False), json.dumps([x.model_dump() for x in data.tests], ensure_ascii=False), data.time_limit, data.memory_mb, int(time.time()), task_id))
    return {"ok": True, "id": task_id}


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        row = c.execute("SELECT id FROM tasks WHERE id=? AND owner_id=?", (task_id, user["id"])).fetchone()
        if not row: raise HTTPException(404, "Задача не найдена")
        # Do not silently break existing contests.
        used = c.execute("SELECT id,task_ids FROM contests WHERE owner_id=?", (user["id"],)).fetchall()
        if any(task_id in json.loads(x["task_ids"]) for x in used):
            raise HTTPException(409, "Сначала удали задачу из контестов или удали сами контесты")
        c.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    return {"ok": True}


@app.get("/api/contests")
def list_contests(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT id,title,invite_code,task_ids,duration_minutes,created_at FROM contests WHERE owner_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return [{"id": r["id"], "title": r["title"], "invite_code": r["invite_code"], "task_count": len(json.loads(r["task_ids"])), "duration_minutes": r["duration_minutes"], "created_at": r["created_at"]} for r in rows]


@app.post("/api/contests")
def create_contest(data: ContestIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        owned = {r["id"] for r in c.execute("SELECT id FROM tasks WHERE owner_id=?", (user["id"],)).fetchall()}
        if not set(data.task_ids).issubset(owned): raise HTTPException(400, "Контест может включать только твои задачи")
        code = secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:10].upper()
        cur = c.execute("INSERT INTO contests(owner_id,title,invite_code,task_ids,duration_minutes,created_at) VALUES(?,?,?,?,?,?)", (user["id"], data.title.strip(), code, json.dumps(data.task_ids), data.duration_minutes, int(time.time())))
    return {"id": cur.lastrowid, "title": data.title.strip(), "invite_code": code, "share_url": f"?contest={code}"}


@app.delete("/api/contests/{contest_id}")
def delete_contest(contest_id: int, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        cur = c.execute("DELETE FROM contests WHERE id=? AND owner_id=?", (contest_id, user["id"]))
        if not cur.rowcount: raise HTTPException(404, "Контест не найден")
    return {"ok": True}


@app.get("/api/contests/{code}")
def get_contest(code: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    with connect() as c:
        contest = c.execute("SELECT * FROM contests WHERE invite_code=?", (code.upper(),)).fetchone()
        if not contest: raise HTTPException(404, "Контест не найден")
        ids = json.loads(contest["task_ids"])
        if user["role"] == "student":
            c.execute("INSERT OR IGNORE INTO participants(contest_id,user_id,joined_at) VALUES(?,?,?)", (contest["id"], user["id"], int(time.time())))
            participant = c.execute("SELECT joined_at FROM participants WHERE contest_id=? AND user_id=?", (contest["id"], user["id"])).fetchone()
            ends_at = participant["joined_at"] + contest["duration_minutes"] * 60
        else:
            ends_at = None
        tasks = []
        for tid in ids:
            row = c.execute("SELECT id,title,statement,examples,time_limit,memory_mb FROM tasks WHERE id=?", (tid,)).fetchone()
            if row: tasks.append({"id": row["id"], "title": row["title"], "statement": row["statement"], "examples": json.loads(row["examples"]), "time_limit": row["time_limit"], "memory_mb": row["memory_mb"]})
    return {"id": contest["id"], "title": contest["title"], "invite_code": contest["invite_code"], "duration_minutes": contest["duration_minutes"], "ends_at": ends_at, "server_time": int(time.time()), "is_owner": user["id"] == contest["owner_id"], "tasks": tasks}


def run_program(language: str, source: str, stdin: str, time_limit: float, memory_mb: int):
    """Local, unsandboxed runner. Suitable only for a trusted, local classroom environment."""
    if not ALLOW_UNSAFE_RUNNER:
        return "RUNNER_DISABLED", "Проверка кода отключена. Включи ALLOW_UNSAFE_RUNNER=1 только для доверенного локального использования."
    with tempfile.TemporaryDirectory(prefix="algoarena_") as temp:
        work = Path(temp)
        env = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        if language == "python":
            script = work / "main.py"; script.write_text(source, encoding="utf-8")
            cmd = [PYTHON_BIN, "-I", "-B", str(script)]
        else:
            if not CPP_BIN:
                return "RUNNER_ERROR", "Не найден компилятор g++. Установи MinGW-w64 или MSYS2 и добавь g++ в PATH."
            script = work / "main.cpp"; binary = work / ("main.exe" if os.name == "nt" else "main")
            script.write_text(source, encoding="utf-8")
            try:
                compiled = subprocess.run([CPP_BIN, "-std=c++20", "-O2", "-pipe", str(script), "-o", str(binary)], cwd=temp, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, errors="replace")
            except subprocess.TimeoutExpired:
                return "COMPILATION_ERROR", "Превышено время компиляции (20 секунд)."
            if compiled.returncode:
                return "COMPILATION_ERROR", (compiled.stderr or compiled.stdout)[-4000:]
            cmd = [str(binary)]
        try:
            proc = subprocess.run(cmd, cwd=temp, env=env, input=stdin, capture_output=True, text=True, timeout=time_limit, errors="replace")
            if proc.returncode != 0:
                return "RUNTIME_ERROR", (proc.stderr or f"Процесс завершился с кодом {proc.returncode}")[-2000:]
            return "OK", proc.stdout[:20000]
        except subprocess.TimeoutExpired as exc:
            return "TIME_LIMIT_EXCEEDED", (exc.stdout or b"").decode("utf-8", "replace")[:1000] if isinstance(exc.stdout, bytes) else (exc.stdout or "")[:1000]
        except OSError as exc:
            return "RUNNER_ERROR", str(exc)


@app.post("/api/submit")
def submit(data: SubmitIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if data.language not in ("cpp", "python"): raise HTTPException(400, "Выбери C++20 или Python 3.13")
    with connect() as c:
        task = c.execute("SELECT * FROM tasks WHERE id=?", (data.task_id,)).fetchone()
        if not task: raise HTTPException(404, "Задача не найдена")
        contest_id = None
        if data.contest_code:
            contest = c.execute("SELECT * FROM contests WHERE invite_code=?", (data.contest_code.upper(),)).fetchone()
            if not contest or data.task_id not in json.loads(contest["task_ids"]): raise HTTPException(403, "Эта задача не входит в контест")
            contest_id = contest["id"]
            if user["role"] == "student":
                participant = c.execute("SELECT joined_at FROM participants WHERE contest_id=? AND user_id=?", (contest_id, user["id"])).fetchone()
                if not participant: raise HTTPException(403, "Сначала открой контест по пригласительному коду")
                if int(time.time()) > participant["joined_at"] + contest["duration_minutes"] * 60: raise HTTPException(403, "Время контеста истекло")
        tests = json.loads(task["tests"])
    passed = 0; verdict = "ACCEPTED"; details = []
    for i, case in enumerate(tests, 1):
        status, output = run_program(data.language, data.source, str(case["input"]), float(task["time_limit"]), int(task["memory_mb"]))
        ok = status == "OK" and output.strip() == str(case["output"]).strip()
        if ok:
            passed += 1
        else:
            verdict = status if status != "OK" else "WRONG_ANSWER"
            details.append({"test": i, "verdict": verdict, "message": output[:2000], "expected": str(case["output"])[:500] if user["role"] == "teacher" else None, "actual": output[:500] if user["role"] == "teacher" else None})
            break
    if passed == len(tests): verdict = "ACCEPTED"
    with connect() as c:
        cur = c.execute("INSERT INTO submissions(user_id,task_id,contest_id,language,source,verdict,passed,total,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (user["id"], data.task_id, contest_id, data.language, data.source, verdict, passed, len(tests), int(time.time())))
        sid = cur.lastrowid
    return {"id": sid, "verdict": verdict, "passed": passed, "total": len(tests), "details": details, "runner_enabled": ALLOW_UNSAFE_RUNNER}


@app.get("/api/submissions")
def my_submissions(authorization: Optional[str] = Header(None), contest_code: Optional[str] = Query(None), limit: int = Query(30, ge=1, le=100)):
    user = current_user(authorization)
    with connect() as c:
        sql = "SELECT s.id,s.task_id,t.title AS task_title,s.contest_id,s.language,s.verdict,s.passed,s.total,s.created_at FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=?"
        args: list = [user["id"]]
        if contest_code:
            con = c.execute("SELECT id FROM contests WHERE invite_code=?", (contest_code.upper(),)).fetchone()
            if not con: raise HTTPException(404, "Контест не найден")
            sql += " AND s.contest_id=?"; args.append(con["id"])
        sql += " ORDER BY s.id DESC LIMIT ?"; args.append(limit)
        return [dict(r) for r in c.execute(sql, args).fetchall()]


@app.get("/api/leaderboard/{code}")
def leaderboard(code: str, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    with connect() as c:
        contest = c.execute("SELECT id,task_ids FROM contests WHERE invite_code=?", (code.upper(),)).fetchone()
        if not contest: raise HTTPException(404, "Контест не найден")
        rows = c.execute("""SELECT u.username, SUM(best.passed) AS score, SUM(best.accepted) AS solved, SUM(best.attempts) AS attempts, MAX(best.last_submit) AS last_submit
          FROM users u JOIN (
            SELECT user_id,task_id,MAX(passed) AS passed,MAX(CASE WHEN verdict='ACCEPTED' THEN 1 ELSE 0 END) AS accepted,COUNT(*) AS attempts,MAX(created_at) AS last_submit
            FROM submissions WHERE contest_id=? GROUP BY user_id,task_id
          ) best ON best.user_id=u.id GROUP BY u.id ORDER BY solved DESC, score DESC, attempts ASC, last_submit ASC""", (contest["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/teacher/submissions")
def teacher_submissions(authorization: Optional[str] = Header(None), contest_code: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=500)):
    user = current_user(authorization); require_teacher(user)
    with connect() as c:
        sql = "SELECT s.id,u.username,t.title AS task_title,s.language,s.verdict,s.passed,s.total,s.created_at,s.source FROM submissions s JOIN users u ON u.id=s.user_id JOIN tasks t ON t.id=s.task_id JOIN contests co ON co.id=s.contest_id WHERE co.owner_id=?"
        args: list = [user["id"]]
        if contest_code:
            sql += " AND co.invite_code=?"; args.append(contest_code.upper())
        sql += " ORDER BY s.id DESC LIMIT ?"; args.append(limit)
        return [dict(r) for r in c.execute(sql, args).fetchall()]
