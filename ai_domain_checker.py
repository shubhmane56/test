"""
ai_domain_checker.py

Purpose:
    Test connectivity to a broad list of AI-related domains (chatbots, coding
    assistants, image/video/voice generators, writing tools, etc.) from the
    current network to determine which are BLOCKED and which are ALLOWED by
    your company's firewall, proxy, or web-filtering policy.

    Useful for spotting "shadow AI" - unapproved AI tools that employees may
    be using outside of sanctioned/company-approved services.

    This performs read-only checks only:
      1. DNS resolution of the domain.
      2. An HTTPS HEAD request to the domain (falls back gracefully if the
         server rejects HEAD).

    It does NOT attempt to bypass, tunnel through, or circumvent any
    security control - it simply reports what the network currently allows.

Usage:
    python ai_domain_checker.py
    python ai_domain_checker.py --input domains.txt
    python ai_domain_checker.py --output results.csv --timeout 8

    domains.txt format: one domain per line, "#" for comments, e.g.
        # AI chat tools
        chat.openai.com
        claude.ai
"""

import argparse
import csv
import socket
import ssl
import sys
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Default list of AI-related domains, grouped by category for readability.
# Edit this list, or supply your own with --input domains.txt
DEFAULT_DOMAINS = [
    # --- OpenAI ---
    "openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "platform.openai.com",
    # --- Anthropic (Claude) ---
    "claude.ai",
    "anthropic.com",
    "console.anthropic.com",
    # --- Google ---
    "bard.google.com",
    "gemini.google.com",
    "aistudio.google.com",
    "labs.google",
    # --- Microsoft ---
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    # --- xAI ---
    "x.ai",
    "grok.com",
    # --- Meta ---
    "meta.ai",
    # --- Perplexity ---
    "perplexity.ai",
    # --- Mistral ---
    "mistral.ai",
    "chat.mistral.ai",
    "lechat.mistral.ai",
    # --- DeepSeek ---
    "deepseek.com",
    "chat.deepseek.com",
    # --- Alibaba Qwen ---
    "qwen.ai",
    "chat.qwen.ai",
    "tongyi.aliyun.com",
    # --- Baidu ---
    "yiyan.baidu.com",
    "ernie.baidu.com",
    # --- Zhipu / Moonshot (Chinese AI assistants) ---
    "chatglm.cn",
    "moonshot.cn",
    "moonshot.ai",
    "kimi.moonshot.cn",
    "kimi.ai",
    # --- Inflection ---
    "pi.ai",
    "inflection.ai",
    # --- Character / general chat ---
    "character.ai",
    "poe.com",
    "you.com",
    # --- Model providers / infra ---
    "groq.com",
    "together.ai",
    "cohere.com",
    "cohere.ai",
    "ai21.com",
    "huggingface.co",
    # --- AI coding assistants ---
    "cursor.sh",
    "cursor.com",
    "tabnine.com",
    "codeium.com",
    "windsurf.com",
    "sourcegraph.com",
    "replit.com",
    "v0.dev",
    "bolt.new",
    "lovable.dev",
    # --- Image / video / voice generation ---
    "midjourney.com",
    "stability.ai",
    "dreamstudio.ai",
    "runwayml.com",
    "pika.art",
    "lumalabs.ai",
    "firefly.adobe.com",
    "leonardo.ai",
    "elevenlabs.io",
    "synthesia.io",
    "suno.ai",
    "udio.com",
    "descript.com",
    # --- Writing / productivity ---
    "notion.ai",
    "jasper.ai",
    "writesonic.com",
    "copy.ai",
    "rytr.me",
    "grammarly.com",
    "quillbot.com",
    "gamma.app",
    "otter.ai",
    "fireflies.ai",
    # --- Translation ---
    "deepl.com",
    # --- Misc / aggregators ---
    "phind.com",
    "replicate.com",
    "abacus.ai",
]


def check_dns(domain, timeout=5):
    """Attempt DNS resolution for a domain. Returns (ok, error_message)."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True, None
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    except socket.timeout:
        return False, "DNS resolution timed out"


def check_https(domain, timeout=5):
    """Attempt an HTTPS HEAD request. Returns (ok, status_code_or_error)."""
    url = f"https://{domain}"
    try:
        ctx = ssl.create_default_context()
        req = Request(
            url,
            method="HEAD",
            headers={"User-Agent": "Mozilla/5.0 (compatible; AIDomainChecker/1.0)"},
        )
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return True, resp.status
    except HTTPError as e:
        # Server actually responded (even an error code) => network path is open
        return True, e.code
    except URLError as e:
        return False, f"Connection failed: {e.reason}"
    except socket.timeout:
        return False, "Connection timed out"
    except Exception as e:  # noqa: BLE001 - report any unexpected failure
        return False, f"Unexpected error: {e}"


def test_domain(domain, timeout=5):
    """Run DNS + HTTPS checks for a single domain and return a result dict."""
    result = {
        "domain": domain,
        "dns_resolved": False,
        "dns_error": None,
        "https_reachable": False,
        "https_status_or_error": None,
        "verdict": "BLOCKED",
    }

    dns_ok, dns_err = check_dns(domain, timeout)
    result["dns_resolved"] = dns_ok
    result["dns_error"] = dns_err

    if not dns_ok:
        result["verdict"] = "BLOCKED (DNS)"
        return result

    https_ok, https_info = check_https(domain, timeout)
    result["https_reachable"] = https_ok
    result["https_status_or_error"] = https_info
    result["verdict"] = "ALLOWED" if https_ok else "BLOCKED (Connection)"
    return result


def load_domains(path):
    """Load domains from a text file, one per line, '#' lines are comments."""
    with open(path, "r", encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Test which .ai / AI-related domains are BLOCKED or ALLOWED "
            "on the current network (e.g. your company firewall/proxy)."
        )
    )
    parser.add_argument(
        "--input", "-i",
        help="Path to a text file with one domain per line. Defaults to a built-in list.",
    )
    parser.add_argument(
        "--output", "-o",
        default="ai_domain_check_results.csv",
        help="CSV file to write detailed results to (default: ai_domain_check_results.csv).",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=5.0,
        help="Timeout in seconds per check (default: 5).",
    )
    args = parser.parse_args()

    domains = load_domains(args.input) if args.input else DEFAULT_DOMAINS

    print(f"Testing {len(domains)} domain(s) with a {args.timeout}s timeout...\n")
    print(f"{'DOMAIN':<28} {'VERDICT':<22} {'DETAILS'}")
    print("-" * 80)

    results = []
    for domain in domains:
        r = test_domain(domain, timeout=args.timeout)
        detail = r["dns_error"] or r["https_status_or_error"] or "OK"
        print(f"{r['domain']:<28} {r['verdict']:<22} {detail}")
        results.append(r)
        sys.stdout.flush()

    allowed = [r for r in results if r["verdict"] == "ALLOWED"]
    blocked = [r for r in results if r["verdict"] != "ALLOWED"]

    print("\nSummary")
    print("-" * 80)
    print(f"Total tested : {len(results)}")
    print(f"Allowed      : {len(allowed)}")
    print(f"Blocked      : {len(blocked)}")

    checked_at = datetime.now().isoformat(timespec="seconds")
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "domain",
                "verdict",
                "dns_resolved",
                "dns_error",
                "https_reachable",
                "https_status_or_error",
                "checked_at",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r["domain"],
                    r["verdict"],
                    r["dns_resolved"],
                    r["dns_error"] or "",
                    r["https_reachable"],
                    r["https_status_or_error"] or "",
                    checked_at,
                ]
            )

    print(f"\nDetailed results written to: {args.output}")


if __name__ == "__main__":
    main()
