# Copyright (c) 2026 egraich

import aiosqlite
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_stats.db")

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ai_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                score INTEGER
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS vt_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                malicious INTEGER,
                total INTEGER
            )
        """)
        await db.commit()

async def log_ai_scan(score: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO ai_scans (score) VALUES (?)", (score,))
        await db.commit()

async def log_vt_scan(malicious: int, total: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO vt_scans (malicious, total) VALUES (?, ?)", (malicious, total))
        await db.commit()