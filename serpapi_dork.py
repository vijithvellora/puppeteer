#!/usr/bin/env python3
"""Run a Google dork via SerpAPI and save results to .txt and .md files."""

import sys
import json
import urllib.request
import urllib.parse
from datetime import datetime

API_KEY = "8369529ceeebd55a039e7e8571fb84dae4c283a3ea9708eb4dcbf7c252786fb3"
BASE_URL = "https://serpapi.com/search.json"


def search(query: str) -> dict:
    params = urllib.parse.urlencode({
        "q": query,
        "engine": "google",
        "api_key": API_KEY,
        "num": 10,
    })
    url = f"{BASE_URL}?{params}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode())


def format_txt(query: str, data: dict, timestamp: str) -> str:
    lines = [
        f"SerpAPI Results",
        f"Query   : {query}",
        f"Time    : {timestamp}",
        "=" * 60,
        "",
    ]
    results = data.get("organic_results", [])
    if not results:
        lines.append("No organic results found.")
    for i, r in enumerate(results, 1):
        lines += [
            f"[{i}] {r.get('title', 'N/A')}",
            f"    URL  : {r.get('link', 'N/A')}",
            f"    Snip : {r.get('snippet', 'N/A')}",
            "",
        ]
    return "\n".join(lines)


def format_md(query: str, data: dict, timestamp: str) -> str:
    lines = [
        f"# SerpAPI Dork Results",
        f"",
        f"**Query:** `{query}`  ",
        f"**Time:** {timestamp}",
        "",
        "---",
        "",
    ]
    results = data.get("organic_results", [])
    if not results:
        lines.append("_No organic results found._")
    for i, r in enumerate(results, 1):
        title = r.get("title", "N/A")
        link = r.get("link", "N/A")
        snippet = r.get("snippet", "N/A")
        lines += [
            f"### {i}. [{title}]({link})",
            f"",
            f"{snippet}",
            f"",
            f"**URL:** <{link}>",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 serpapi_dork.py \"your dork here\"")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    slug = query[:40].replace(" ", "_").replace('"', "").replace(":", "-")

    print(f"[*] Searching: {query}")
    data = search(query)

    txt_path = f"results_{slug}.txt"
    md_path  = f"results_{slug}.md"

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(format_txt(query, data, timestamp))

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(format_md(query, data, timestamp))

    print(f"[+] Saved  → {txt_path}")
    print(f"[+] Saved  → {md_path}")
    n = len(data.get("organic_results", []))
    print(f"[+] {n} organic result(s) written.")


if __name__ == "__main__":
    main()
