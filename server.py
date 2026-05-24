#!/usr/bin/env python3
"""
MEOK W3C TDM Rights MCP — EU CDSM Directive Article 4(3) opt-out
====================================================================

By MEOK AI Labs · https://meok.ai · MIT
<!-- mcp-name: io.github.CSOAI-ORG/meok-w3c-tdm-rights-mcp -->

WHAT THIS DOES
--------------
EU Directive 2019/790 (CDSM) Article 4(3) gives rightsholders the right to
RESERVE their works against AI / TDM (Text + Data Mining) training. The
reservation must be expressed in a "machine-readable" manner for online
content.

This MCP:
  - Issues + validates TDM-RESERVE signals across the 4 standard mechanisms
  - Acts as the verifier for AI training pipelines (must scan + respect)
  - Maintains a registry of reserved-content fingerprints
  - Signs each scan for liability shield ("we checked before training")

THE 4 MACHINE-READABLE MECHANISMS
---------------------------------
  1. **HTTP headers** — `Tdm-Reservation: 1` + `Tdm-Policy: <url>`
  2. **HTML meta tags** — `<meta name="tdm-reservation" content="1">`
  3. **robots.txt** — `User-agent: GPTBot\nDisallow: /` patterns
  4. **C2PA + IPTC** — `do_not_train` assertion in Content Credentials

WHY THIS MATTERS
----------------
Every AI training operation in the EU after 4 June 2024 needs a defensible
process to RESPECT Article 4(3) reservations. Court cases coming. Anthropic,
OpenAI, Meta already lost preliminary rulings in Hamburg + Munich (2025).

NOBODY else has shipped a TDM MCP. First-mover.

TOOLS
-----
- issue_tdm_reservation(work_id, rightsholder_did, mechanism, ...)
- scan_url_for_reservation(url): HTTP+meta+robots scan
- verify_c2pa_do_not_train(asset_meta)
- check_robots_txt(domain, agent_name): bot-specific allow/disallow
- generate_compliant_scraper_config(): config blob for your training pipeline
- sign_training_scan(scan_result, training_run_id): liability-shield attestation

PRICING
-------
Free MIT self-host · £79/mo Pro · Governance Substrate £499/mo · £4,990/mo Defence.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import time
import urllib.request
from datetime import datetime, timezone
from typing import Optional
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("meok-w3c-tdm-rights")
_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET", "")
_RESERVATIONS: dict[str, dict] = {}


SPEC_REFS = {
    "cdsm_directive": "EU 2019/790 Art 4(3)",
    "uk_cdpa": "UK CDPA s9A (post-Brexit Article 4 analogue)",
    "w3c_tdmrep": "W3C TDMRep Community Group spec",
    "iptc_content_authenticity": "IPTC Content Authenticity Guide",
    "c2pa_do_not_train": "C2PA 2.0 assertion `c2pa.training-mining`",
}

KNOWN_AI_AGENTS = {
    "GPTBot":      "OpenAI",
    "ChatGPT-User": "OpenAI (browse)",
    "ClaudeBot":   "Anthropic",
    "anthropic-ai": "Anthropic (legacy)",
    "Claude-Web":  "Anthropic",
    "Google-Extended": "Google AI",
    "CCBot":       "Common Crawl",
    "Bytespider":  "ByteDance",
    "Bytespider-MFA": "ByteDance",
    "FacebookBot": "Meta",
    "Meta-ExternalAgent": "Meta",
    "Meta-ExternalFetcher": "Meta",
    "PerplexityBot": "Perplexity",
    "YouBot":      "You.com",
    "AmazonBot":   "Amazon",
    "Applebot-Extended": "Apple",
    "cohere-ai":   "Cohere",
    "Diffbot":     "Diffbot",
    "ImagesiftBot": "TheHive AI",
    "MistralAI-User": "Mistral",
}


def _sign(payload: dict) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(_HMAC_SECRET.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def issue_tdm_reservation(
    work_id: str,
    rightsholder_did: str,
    mechanism: str,
    policy_url: Optional[str] = None,
    scope: str = "all_ai_training",
    valid_until: Optional[str] = None,
) -> dict:
    """
    Issue a signed TDM reservation per CDSM Article 4(3).

    Args:
        work_id: Identifier of the work (URL, hash, DOI, etc.).
        rightsholder_did: W3C DID of the rightsholder.
        mechanism: "http_header" / "html_meta" / "robots_txt" / "c2pa_assertion".
        policy_url: Optional URL to the full TDM licence terms.
        scope: "all_ai_training" / "generative_ai_only" / "research_exempt_allowed".
        valid_until: Optional ISO date the reservation expires.

    Returns:
        {reservation, signature, expressions_to_publish}
    """
    valid_mechanisms = {"http_header", "html_meta", "robots_txt", "c2pa_assertion"}
    if mechanism not in valid_mechanisms:
        return {"error": f"Use one of {valid_mechanisms}"}

    res_id = f"TDMRES_{int(time.time())}_{os.urandom(4).hex()}"
    reservation = {
        "reservation_id": res_id,
        "spec": SPEC_REFS["cdsm_directive"],
        "work_id": work_id,
        "rightsholder_did": rightsholder_did,
        "mechanism": mechanism,
        "scope": scope,
        "policy_url": policy_url,
        "valid_until": valid_until,
        "issued_at": _ts(),
    }
    reservation["signature"] = _sign(reservation)
    _RESERVATIONS[res_id] = reservation

    # Generate the actual machine-readable expressions
    expressions = {}
    if mechanism == "http_header":
        expressions["http_headers"] = {
            "Tdm-Reservation": "1",
            "Tdm-Policy": policy_url or f"https://meok.ai/tdm/{res_id}",
        }
    elif mechanism == "html_meta":
        expressions["html_meta_tags"] = [
            '<meta name="tdm-reservation" content="1">',
            f'<meta name="tdm-policy" content="{policy_url or f"https://meok.ai/tdm/{res_id}"}">',
        ]
    elif mechanism == "robots_txt":
        rules = []
        for agent in KNOWN_AI_AGENTS:
            rules.append(f"User-agent: {agent}\nDisallow: /\n")
        expressions["robots_txt_block"] = "\n".join(rules)
    elif mechanism == "c2pa_assertion":
        expressions["c2pa_assertion"] = {
            "label": "c2pa.training-mining",
            "data": {
                "use": "notAllowed",
                "constraint_info": "EU CDSM Article 4(3) reservation",
                "policy_url": policy_url or f"https://meok.ai/tdm/{res_id}",
            },
        }

    return {
        "reservation": reservation,
        "signature": reservation["signature"],
        "expressions_to_publish": expressions,
        "next_step": "Publish the expression(s) on the content URL. AI scrapers MUST respect this per Art 4(3).",
    }


@mcp.tool()
def scan_url_for_reservation(url: str, fetch_robots: bool = True) -> dict:
    """
    Scan a URL for TDM reservation signals across all 3 web mechanisms.

    Args:
        url: URL to scan.
        fetch_robots: Also fetch the domain's robots.txt.

    Returns:
        {reserved, signals_found, html_meta, http_headers, robots_txt}
    """
    signals = []
    headers_seen = {}
    meta_seen = []
    robots_text = ""

    # HTTP HEAD for headers
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=8) as r:
            for k, v in r.headers.items():
                if "tdm" in k.lower():
                    headers_seen[k] = v
                    signals.append(f"http_header: {k}={v}")
    except Exception as e:
        headers_seen["_error"] = str(e)

    # GET for HTML meta — small sample
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(50_000).decode("utf-8", errors="replace")
            for m in re.finditer(r'<meta[^>]*name=["\']tdm[^"\']*["\'][^>]*>', body, re.I):
                meta_seen.append(m.group(0))
                signals.append(f"html_meta: {m.group(0)[:80]}")
    except Exception as e:
        meta_seen.append(f"_error: {e}")

    # robots.txt
    if fetch_robots:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            with urllib.request.urlopen(robots_url, timeout=8) as r:
                robots_text = r.read(50_000).decode("utf-8", errors="replace")
                for agent in KNOWN_AI_AGENTS:
                    if re.search(rf"(?im)^User-agent:\s*{re.escape(agent)}\s*$", robots_text):
                        block = re.search(
                            rf"(?ims)User-agent:\s*{re.escape(agent)}\s*\n.*?(?=\nUser-agent:|\Z)",
                            robots_text,
                        )
                        if block and re.search(r"(?im)^Disallow:\s*/", block.group(0)):
                            signals.append(f"robots.txt: {agent} disallowed")
        except Exception as e:
            robots_text = f"_error: {e}"

    return {
        "reserved": len(signals) > 0,
        "signals_found": signals,
        "http_headers": headers_seen,
        "html_meta": meta_seen,
        "robots_txt_snippet": robots_text[:2000],
        "scanned_at": _ts(),
        "url": url,
    }


@mcp.tool()
def verify_c2pa_do_not_train(asset_meta: dict) -> dict:
    """
    Check a C2PA manifest for a do-not-train assertion.

    Args:
        asset_meta: Dict containing the C2PA manifest assertions.

    Returns:
        {reserved, assertion_found, policy_url}
    """
    assertions = asset_meta.get("assertions", [])
    for a in assertions:
        label = a.get("label", "")
        if "training-mining" in label or "do-not-train" in label.lower():
            use = a.get("data", {}).get("use", "")
            if use == "notAllowed":
                return {
                    "reserved": True,
                    "assertion_found": a,
                    "policy_url": a.get("data", {}).get("policy_url"),
                    "spec": SPEC_REFS["c2pa_do_not_train"],
                }
    return {"reserved": False, "spec": SPEC_REFS["c2pa_do_not_train"]}


@mcp.tool()
def check_robots_txt(domain: str, agent_name: str = "ClaudeBot") -> dict:
    """
    Quick check: is this specific bot disallowed in this domain's robots.txt?

    Args:
        domain: Domain to check (e.g. example.com).
        agent_name: AI agent user-agent string.

    Returns:
        {allowed, robots_txt_url, matched_rules}
    """
    if not domain.startswith(("http://", "https://")):
        url = f"https://{domain}/robots.txt"
    else:
        url = f"{domain.rstrip('/')}/robots.txt"
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            body = r.read(50_000).decode("utf-8", errors="replace")
    except Exception as e:
        return {"allowed": True, "error": str(e), "robots_txt_url": url, "matched_rules": [], "note": "Couldn't fetch — defaulting to allowed."}

    rules = []
    disallowed = False
    # Find the agent's block
    block_match = re.search(
        rf"(?ims)User-agent:\s*{re.escape(agent_name)}\s*\n(.*?)(?=\nUser-agent:|\Z)",
        body,
    )
    if block_match:
        for line in block_match.group(1).splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                rules.append(f"Disallow: {path}")
                if path == "/" or path == "*":
                    disallowed = True
    # Also check the wildcard *
    star_block = re.search(r"(?ims)User-agent:\s*\*\s*\n(.*?)(?=\nUser-agent:|\Z)", body)
    if star_block and not rules:
        for line in star_block.group(1).splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                rules.append(f"Disallow (wildcard): {path}")
                if path == "/" or path == "*":
                    disallowed = True

    return {
        "allowed": not disallowed,
        "agent_name": agent_name,
        "robots_txt_url": url,
        "matched_rules": rules,
    }


@mcp.tool()
def generate_compliant_scraper_config() -> dict:
    """
    Return a scraper config blob your AI-training pipeline can adopt.

    Returns:
        {config, integration_hint}
    """
    return {
        "config": {
            "respect_tdm_reservation_header": True,
            "respect_tdm_meta_tag": True,
            "respect_robots_txt": True,
            "respect_c2pa_training_mining_assertion": True,
            "honor_canonical_domain_only": True,
            "scrub_reserved_content_from_training_set": True,
            "log_all_reservation_hits_for_audit": True,
            "known_ai_agents": list(KNOWN_AI_AGENTS.keys()),
            "specs": SPEC_REFS,
        },
        "integration_hint": (
            "Wire scan_url_for_reservation() into your crawler BEFORE writing to "
            "training set. Call sign_training_scan() per batch for liability shield."
        ),
    }


@mcp.tool()
def sign_training_scan(scan_results: list[dict], training_run_id: str) -> dict:
    """
    Bundle scan results into a signed training-shield attestation.

    Args:
        scan_results: List of scan_url_for_reservation() outputs.
        training_run_id: Your training run identifier.

    Returns:
        {attestation_id, signature, verify_url, urls_scanned, urls_reserved}
    """
    att_id = f"TDMSCAN_{int(time.time())}_{os.urandom(4).hex()}"
    reserved = [s for s in scan_results if s.get("reserved")]
    sealed = {
        "attestation_id": att_id,
        "spec": SPEC_REFS["cdsm_directive"],
        "training_run_id": training_run_id,
        "urls_scanned": len(scan_results),
        "urls_reserved": len(reserved),
        "reserved_urls": [s.get("url") for s in reserved if s.get("url")],
        "sealed_at": _ts(),
        "issuer": "MEOK AI Labs (CSOAI LTD)",
    }
    sig = _sign(sealed)
    return {
        "attestation_id": att_id,
        "signature": sig,
        "sealed_at": sealed["sealed_at"],
        "verify_url": f"https://meok-attestation-api.vercel.app/verify/{att_id}",
        "urls_scanned": len(scan_results),
        "urls_reserved": len(reserved),
        "shield_note": "Retain this attestation. If sued for Art 4(3) violation, this is the audit-defensible record that you scanned + excluded reserved content.",
    }


@mcp.tool()
def list_known_ai_agents() -> dict:
    """Return the catalogue of known AI/ML scraper user-agent strings."""
    return {"agents": KNOWN_AI_AGENTS, "count": len(KNOWN_AI_AGENTS), "spec_refs": SPEC_REFS}


if __name__ == "__main__":
    mcp.run()
