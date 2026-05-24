"""Smoke tests for meok-w3c-tdm-rights-mcp."""
import sys, os, inspect, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import (
    issue_tdm_reservation,
    verify_c2pa_do_not_train,
    generate_compliant_scraper_config,
    sign_training_scan,
    list_known_ai_agents,
    KNOWN_AI_AGENTS,
    _RESERVATIONS,
)


def test_issue_reservation_http_header():
    _RESERVATIONS.clear()
    r = issue_tdm_reservation("https://example.com/article", "did:web:rightsholder.example", "http_header", policy_url="https://example.com/tdm-policy")
    assert r["reservation"]["reservation_id"].startswith("TDMRES_")
    assert "Tdm-Reservation" in r["expressions_to_publish"]["http_headers"]


def test_issue_reservation_html_meta():
    _RESERVATIONS.clear()
    r = issue_tdm_reservation("https://example.com/article", "did:web:x", "html_meta")
    assert any("tdm-reservation" in tag for tag in r["expressions_to_publish"]["html_meta_tags"])


def test_issue_reservation_robots_txt():
    _RESERVATIONS.clear()
    r = issue_tdm_reservation("https://example.com/", "did:web:x", "robots_txt")
    assert "GPTBot" in r["expressions_to_publish"]["robots_txt_block"]
    assert "ClaudeBot" in r["expressions_to_publish"]["robots_txt_block"]


def test_issue_reservation_c2pa():
    _RESERVATIONS.clear()
    r = issue_tdm_reservation("ipfs://Qm...", "did:web:photographer", "c2pa_assertion", policy_url="https://photog.example/licence")
    assert r["expressions_to_publish"]["c2pa_assertion"]["data"]["use"] == "notAllowed"


def test_issue_reservation_unknown_mechanism():
    r = issue_tdm_reservation("u", "did:x", "skywriting")
    assert "error" in r


def test_verify_c2pa_do_not_train_detects():
    asset = {
        "assertions": [
            {"label": "c2pa.training-mining", "data": {"use": "notAllowed", "policy_url": "https://example.com/p"}},
        ],
    }
    r = verify_c2pa_do_not_train(asset)
    assert r["reserved"] is True
    assert r["policy_url"] == "https://example.com/p"


def test_verify_c2pa_do_not_train_absent():
    asset = {"assertions": [{"label": "c2pa.actions"}]}
    r = verify_c2pa_do_not_train(asset)
    assert r["reserved"] is False


def test_generate_scraper_config():
    r = generate_compliant_scraper_config()
    assert r["config"]["respect_tdm_reservation_header"] is True
    assert r["config"]["respect_robots_txt"] is True
    assert "GPTBot" in r["config"]["known_ai_agents"]


def test_sign_training_scan_aggregates():
    scans = [
        {"url": "https://a.example", "reserved": True},
        {"url": "https://b.example", "reserved": False},
        {"url": "https://c.example", "reserved": True},
    ]
    r = sign_training_scan(scans, "training_run_2026_05")
    assert r["urls_scanned"] == 3
    assert r["urls_reserved"] == 2
    assert "verify_url" in r


def test_list_known_ai_agents():
    r = list_known_ai_agents()
    assert "GPTBot" in r["agents"]
    assert "ClaudeBot" in r["agents"]
    assert r["count"] >= 15


if __name__ == "__main__":
    g = dict(globals())
    fns = [v for k, v in g.items() if k.startswith("test_") and inspect.isfunction(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); print(f"OK {fn.__name__}"); p += 1
        except Exception as e:
            print(f"X  {fn.__name__}: {type(e).__name__}: {e}"); traceback.print_exc(); f += 1
    print(f"\n{p} passed, {f} failed")
