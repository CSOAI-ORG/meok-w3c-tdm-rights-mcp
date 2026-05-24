# MEOK W3C TDM Rights MCP

> ## 🧱 Part of the MEOK Governance Substrate (£499/mo) + Defence (£4,990/mo)
> See [meok.ai/governance](https://meok.ai/governance).

# EU CDSM Article 4(3) — TDM opt-out + liability shield for AI training

<!-- mcp-name: io.github.CSOAI-ORG/meok-w3c-tdm-rights-mcp -->

[![PyPI](https://img.shields.io/pypi/v/meok-w3c-tdm-rights-mcp)](https://pypi.org/project/meok-w3c-tdm-rights-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What this does

EU Directive 2019/790 (CDSM) **Article 4(3)** gives rightsholders the right to **RESERVE** their works against AI / TDM training. The reservation must be "machine-readable" for online content.

Court cases are landing: Hamburg + Munich rulings against OpenAI / Meta / Anthropic in 2025. **Every AI training operation in the EU after 4 June 2024 needs a defensible scan-+-respect process.**

This MCP is the first-mover. **Nobody else has shipped an MCP for it.**

## The 4 machine-readable mechanisms

1. **HTTP headers** — `Tdm-Reservation: 1` + `Tdm-Policy: <url>`
2. **HTML meta tags** — `<meta name="tdm-reservation" content="1">`
3. **robots.txt** — `User-agent: GPTBot\nDisallow: /` patterns (20+ AI agents catalogued)
4. **C2PA assertion** — `c2pa.training-mining` with `use: notAllowed`

## Tools

| Tool | Purpose |
|---|---|
| `issue_tdm_reservation(work_id, rightsholder_did, mechanism, ...)` | Issue + emit all 4 expression formats |
| `scan_url_for_reservation(url)` | Triple-scan: HTTP + meta + robots.txt |
| `verify_c2pa_do_not_train(asset_meta)` | C2PA assertion check |
| `check_robots_txt(domain, agent_name)` | Bot-specific allow/disallow |
| `generate_compliant_scraper_config()` | Config blob for your training pipeline |
| `sign_training_scan(scan_results, training_run_id)` | Liability-shield attestation |
| `list_known_ai_agents()` | 20+ AI user-agents catalogued |

## Why this is enterprise-critical

Two pictures of the same risk:

- **For rightsholders** — you NEED machine-readable Article 4(3) signals on your site or you've waived TDM-opt-out rights. This MCP issues them in 4 formats simultaneously.
- **For AI training operators** — you NEED a defensible scan-+-respect process or you'll lose every preliminary injunction in the next round of EU cases. This MCP gives you a per-run signed attestation as your audit-defensible liability shield.

## Sister MCPs

- `meok-c2pa-durable-mcp` — C2PA 2.2 Content Credentials (carries TDM assertions)
- `agent-content-watermark-mcp` — EU AI Act Article 50 watermarking (provider-side companion)
- `agent-data-residency-mcp` — GDPR Chapter V transfer guard
- `bias-detection-mcp` — Article 10 fairness metrics

Full catalogue: [meok.ai/anthropic-registry](https://meok.ai/anthropic-registry)

## Pricing

| Option | Price |
|---|---|
| Self-host MIT | £0 |
| Universal PAYG | £29/mo + £0.0002/call |
| Governance Substrate | £499/mo |
| A2A Substrate | £999/mo |
| **Defence** (training-pipeline scale) | **£4,990/mo** |

Buy: https://meok.ai/governance

## Wire it up — full stack

Pair this with the MEOK chain. See [meok.ai/mcp-stack](https://meok.ai/mcp-stack).

## Licence

MIT. By [MEOK AI Labs](https://meok.ai) (CSOAI LTD, UK Companies House 16939677).
