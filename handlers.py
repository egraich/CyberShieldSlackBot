from slack_bolt.async_app import AsyncApp
from services import SecurityService
from config import Config

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
    async def handle_scamscan(ack, command, client):
        await ack()
        raw_input = command.get("text", "").strip()
        cid = command.get("channel_id")
        
        if not raw_input:
            await client.chat_postMessage(
                channel=cid,
                text="Error: Please provide text or a URL to scan."
            )
            return
            
        initial_msg = await client.chat_postMessage(
            channel=cid,
            text="Wait for analysis..."
        )
        msg_ts = initial_msg["ts"]
        
        ai_out = await inspect_payload(raw_input)
        
        await client.chat_update(
            channel=cid,
            ts=msg_ts,
            text=ai_out
        )

    @app.shortcut("scan_message")
    async def handle_shortcut(ack, shortcut, client):
        await ack()
        
        msg_obj = shortcut.get("message", {})
        raw_input = msg_obj.get("text", "").strip()
        uid = shortcut.get("user", {}).get("id")
        cid = shortcut.get("channel", {}).get("id")
        
        if not raw_input:
            await client.chat_postEphemeral(
                channel=cid,
                user=uid,
                text="Error: Cannot scan an empty message."
            )
            return

        initial_msg = await client.chat_postMessage(
            channel=cid,
            text=f"CyberShield Scan Request by <@{uid}>:\nWait for analysis..."
        )
        msg_ts = initial_msg["ts"]
        
        ai_out = await inspect_payload(raw_input)
        
        await client.chat_update(
            channel=cid,
            ts=msg_ts,
            text=f"CyberShield Scan Request by <@{uid}>:\n\n{ai_out}"
        )