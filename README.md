# Phish Triage

A small, Target-inspired dashboard for reviewing suspicious emails. Python 3.10+
only. No pip install, Node.js, database, accounts, or external services required.

## Start

On Windows, double-click **start.bat**. Or open a terminal in this folder:

```bash
python app.py --open
```

On macOS/Linux, use `python3 app.py --open`. The dashboard opens at
`http://127.0.0.1:8000`. Keep the terminal open; press Ctrl+C to stop.
Use `--port 8001` if port 8000 is busy. This is a local, single-user application,
not a public or production web server. Do not expose it through a tunnel or proxy.

## Use

The first view is an explicitly labeled demo of eight fictional emails. Click
**Analyze email** to upload `.eml` files. Each upload replaces the current batch;
it never mixes sample and real email. Limits: 25 files, 10 MiB each, 20 MiB total.
Exact duplicates within a batch are skipped. Invalid emails are listed separately.

Search or filter the inbox, click an email to inspect the reasons, plain-text
preview, authentication claims, links, and attachments. **Mark reviewed** records
an analyst acknowledgment, not a different verdict. **Campaigns** groups similar
reports; suggestions never merge or close anything. **Export results** saves the
current batch as JSON, including previews and review status; treat it as sensitive.

Results and review status exist only in this page's memory. Refreshing resets the
workspace to the demo; closing the tab or clearing the workspace discards results.
The app does not write uploads or results to disk or browser storage. Export first
when you need to keep results. The server runs until you stop it with Ctrl+C.

## What is included

- `app.py`: local server and upload limits.
- `static/`: dashboard HTML, CSS, JavaScript, and favicon.
- `core/`: parsing, scoring, validation, and campaign suggestions.
- `config/`: six editable policy files. Restart after changes.
- `demo.py`: isolated fictional sample emails, generated in memory.
- `start.bat`: Windows launcher.

No tests, CI workflows, audit reports, saved outputs, dependency manifests,
generated bundles, or SOAR deployment templates are included.

## Important boundaries

Analysis uses local rules, not live URL reputation, antivirus, a sandbox, or AI.
Links are not visited, attachments are not executed, and email HTML is never
rendered. No mailbox is connected. No message is deleted or automatically closed.

Uploaded authentication headers are **always untrusted**, regardless of config.
An uploaded message with a low score still requires review; it is not automatically
safe. The malicious threshold defaults to 60 points. Scores are rule points,
not a probability or percentage, and may exceed 100. A related high-risk email can
raise a campaign's effective verdict; individual scores and verdicts remain visible.

Benign and simulation demo examples use isolated synthetic trust only. No upload
parameter can enable this. Demo findings illustrate UI behavior, not detection
accuracy. Forwarded attached originals are not unwrapped through untrusted uploads;
export and inspect the original email itself where possible. Parsing has size,
MIME-depth, and content limits; warnings must be reviewed.

Corporate domains, sender allowlists, brand/domain mappings, and SharePoint tenants
in `config/` are **example policy**, not an authoritative Target configuration.
Verify them for your own environment. Executive-name matching is empty by default.
Campaign matching is heuristic and scoped only to the current batch.

This is an independent Target-inspired design, not an official Target Corporation
product. The app loads no third-party fonts, scripts, trackers, or images.
