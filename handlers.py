# Copyright (c) 2026 egraich

from slack_bolt.async_app import AsyncApp
from services import SecurityService
from config import Config
from database import log_ai_scan, log_vt_scan, DB_PATH
import aiosqlite

def register_handlers(app: AsyncApp, security: SecurityService):
    
    async def inspect_payload(payload_text: str) -> str:
        target_url = security.extract_url(payload_text)
        telemetry = ""
        
        if target_url:
            vt_res = await security.scan_url_virustotal(target_url)
            status = vt_res.get("status")
            
            if status == "success":
                vt_msg = Config.VT_THREAT.format(malicious=vt_res["malicious"], total=vt_res["total"])
                telemetry = Config.VT_SYSTEM_PROMPT.format(vt_data=vt_msg)
            elif status == "not_found":
                telemetry = Config.VT_SYSTEM_PROMPT.format(vt_data=Config.VT_NOT_FOUND)
            elif status == "no_key":
                telemetry = Config.VT_SYSTEM_PROMPT.format(vt_data=Config.VT_NO_KEY)
            else:
                telemetry = Config.VT_SYSTEM_PROMPT.format(vt_data=Config.VT_ERROR.format(code=vt_res.get("code", "unknown")))

        return await security.get_ai_verdict(payload_text, telemetry)

    @app.command("/scamscan")
    async def handle_scamscan(ack, command, respond):
        await ack()
        raw_input = command.get("text", "").strip()
        
        if not raw_input:
            await respond(
                text="Error: Please provide text or a URL to scan.",
                response_type="ephemeral"
            )
            return
            
        await respond(
            text="Wait for analysis...",
            response_type="ephemeral"
        )
        
        ai_out = await inspect_payload(raw_input)

        await respond(
            text=ai_out,
            replace_original=True,
            response_type="ephemeral"
        )

        score = security.parse_risk_score(ai_out)
        if score is not None:
            await log_ai_scan(score)
    
    @app.shortcut("scan_message")
    async def handle_shortcut(ack, shortcut, respond):
        await ack()
        
        msg_obj = shortcut.get("message", {})
        raw_input = msg_obj.get("text", "").strip()
        
        if not raw_input:
            await respond(
                text="Error: Cannot scan an empty message.",
                response_type="ephemeral"
            )
            return

        await respond(
            text="Wait for analysis...",
            response_type="ephemeral"
        )

        ai_out = await inspect_payload(raw_input)

        await respond(
            text=ai_out,
            replace_original=True,
            response_type="ephemeral"
        )

        score = security.parse_risk_score(ai_out)
        if score is not None:
            await log_ai_scan(score)

    @app.command("/scanlink")
    async def handle_scanlink(ack, command, respond):
        await ack()
        raw_input = command.get("text", "").strip()
        target_url = security.extract_url(raw_input)
        if not target_url:
            await respond(
                text="Error: Please provide a valid URL.",
                response_type="ephemeral"
            )
            return

        await respond(
            text="Scanning link... If it's new, this may take up to a minute.",
            response_type="ephemeral"
        )
        
        vt_res = await security.scan_link_deep(target_url)
        status = vt_res.get("status")
        
        if status == "success":
            if vt_res["malicious"] > 0:
                out_text = Config.VT_THREAT.format(malicious=vt_res["malicious"], total=vt_res["total"])
            else:
                out_text = Config.VT_CLEAN.format(total=vt_res["total"])
        elif status == "timeout":
            out_text = Config.VT_TIMEOUT
        elif status == "no_key":
            out_text = Config.VT_NO_KEY
        else:
            out_text = Config.VT_ERROR.format(code=vt_res.get("code", "unknown"))

        await respond(
            text=out_text,
            replace_original=True,
            response_type="ephemeral"
        )

        if vt_res.get("status") == "success":
            await log_vt_scan(vt_res["malicious"], vt_res["total"])

    @app.command("/cyberstats")
    async def handle_cyberstats(ack, respond):
        await ack()
        
        async with aiosqlite.connect(DB_PATH) as db:
            ai_stats = await db.execute_fetchall("SELECT COUNT(*), AVG(score) FROM ai_scans")
            ai_total, ai_avg = ai_stats[0]
            
            vt_stats = await db.execute_fetchall("SELECT COUNT(*), COUNT(CASE WHEN malicious > 0 THEN 1 END) FROM vt_scans")
            vt_total, vt_threats = vt_stats[0]
            vt_threats = vt_threats or 0
            vt_safe = vt_total - vt_threats

        if ai_avg is not None:
            ai_display = f"{round(ai_avg, 1)}%"
        else:
            ai_display = "No valid data (errors/empty)"

        stats_msg = (
            f"*CyberShield Usage Stats:*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"   *AI Scans (`/scamscan`):*\n"
            f"   Total: `{ai_total}`\n"
            f"   Avg Risk Score: `{ai_display}`\n\n"
            f"   *Link Scans (`/scanlink`):*\n"
            f"   Total: `{vt_total}`\n"
            f"   Threats Detected: `{vt_threats}`\n"
            f"   Safe/Clean: `{vt_safe}`"
        )
        
        await respond(text=stats_msg, response_type="ephemeral")