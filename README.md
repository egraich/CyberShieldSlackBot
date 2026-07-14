# CyberShield

A Slack bot that checks messages and links for scams, phishing, and social engineering using LLMs and VirusTotal.

<img width="1615" height="964" alt="image" src="https://github.com/user-attachments/assets/de1a8afe-33bb-4c0a-b9ec-bc3222773290" />

## Quick Start

1. Go to [HackClub Slack Workspace](https://hackclub.enterprise.slack.com).
2. Type `/scamscan` followed by any text or links in any channel or in DM `@CyberShieldBot`:

<img width="955" height="187" alt="image" src="https://github.com/user-attachments/assets/6f1577da-4a5d-400f-8832-586f6cab5fce" />

3. Enjoy the analysis!

<img width="1036" height="384" alt="image" src="https://github.com/user-attachments/assets/98c09727-721e-4884-b02a-8346c47cd75d" />

## Features

* **`/scamscan <text and links>`** – Extracts any URLs from the message, runs a background VirusTotal lookup, and feeds the text along with live threat telemetry directly into Llama 3.3 via Groq to get an accurate risk analysis.
* **`Scan Message` Shortcut** – Native integration with Slack's context menu. Right-click or click the three dots on any message to audit it instantly.
* **`/scanlink <url>`** – Queries the VirusTotal API directly to check if any security engines flag the specific domain or infrastructure.
* **`/cyberstats`** – Shows a quick summary of total scans, detected threats, and the average risk score from the local database.

## Running Your Own Bot

### Requirements
* Python 3.10+
* Groq API Key & VirusTotal API Key
* Your own Slack App: You need to create an app on the Slack API dashboard, enable Socket Mode, grant required bot permissions, and get your Bot Token (`xoxb-`) and App Token (`xapp-`). Check out the **[HackClub Slack Bot Guide](https://stardance.hackclub.com/missions/slack-bot/guide)** for more details.

### Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/egraich/cybershieldslackbot.git
    cd cybershieldslackbot
    ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the root folder and add your secret tokens:
   ```
   SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
   SLACK_APP_TOKEN=xapp-your-slack-app-token
   GROQ_API_KEY=your-groq-key
   VIRUSTOTAL_API_KEY=your-vt-key
   ```

4. Launch the bot instance:
   ```bash
   python main.py
   ```

## How It Works

The entire backend is built using async libraries (`slack-bolt`, `aiohttp`, and `aiosqlite`). To prevent file-locking crashes when multiple users trigger scans simultaneously, the database is initialized in WAL (Write-Ahead Logging) mode.

For 24/7 uptime, the bot is deployed on [HackClub Nest](https://nest.hackclub.com) via Docker.

## Credits

* **slack-bolt** – Async Slack framework core.
* **Groq SDK** – Llama 3.3 inference provider.
* **VirusTotal API v3** – URL reputation telemetry.

Made by [egraich](https://github.com/egraich) <3