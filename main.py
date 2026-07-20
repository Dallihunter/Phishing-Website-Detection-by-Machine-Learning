import argparse
import json
import sys

from rich.console import Console

from predict import load_artifacts, classify_url

console = Console()


def format_domain_age(age_days) -> str:
    if age_days is None or age_days < 0:
        return "unknown (WHOIS lookup failed)"
    if age_days < 365:
        return f"{age_days} days"
    return f"{age_days} days (~{age_days / 365:.1f} years)"


def print_result(result: dict) -> None:
    line = "─" * 45
    console.print(line)
    if result["verdict"] == "phishing":
        console.print(f"[bold red]🚨 PHISHING[/bold red]  —  {result['confidence'] * 100:.1f}% confidence")
        if result["reasons"]:
            console.print("\n  Why:")
            for r in result["reasons"]:
                console.print(f"    • {r}")
    else:
        console.print(f"[bold green]✅ LEGITIMATE[/bold green]  —  {result['confidence'] * 100:.1f}% confidence")

    if "domain_age_days" in result:
        console.print(f"\n  Domain age: {format_domain_age(result['domain_age_days'])}")

    console.print(line)

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url


def run_interactive(model, scaler) -> None:
    console.print("\n🔍 [bold]Phishing URL Detector[/bold]")
    console.print("Type a URL to check, or 'q' to quit.\n")

    while True:
        url = input("Enter URL: ").strip()
        if url.lower() == 'q':
            console.print("Goodbye!")
            break
        if not url:
            console.print("Please enter a URL.\n")
            continue
        result = classify_url(normalize_url(url), model, scaler)
        print_result(result)
        console.print()


def run_single(url: str, model, scaler, as_json: bool) -> None:
    result = classify_url(normalize_url(url), model, scaler)
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result)


def run_batch(filepath: str, model, scaler, as_json: bool) -> None:
    with open(filepath) as f:
        urls = [line.strip() for line in f if line.strip()]

    results = [classify_url(normalize_url(u), model, scaler) for u in urls]

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_result(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="🔍 Phishing URL Detector — check if a URL is likely phishing or legitimate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode (type URLs one at a time):
    python3 main.py

  Check a single URL:
    python3 main.py --url https://example.com

  Check a single URL and get machine-readable output:
    python3 main.py --url https://example.com --json

  Check a list of URLs from a file (one URL per line):
    python3 main.py --file urls.txt

  Batch-check a file and output JSON (useful for scripts/pipelines):
    python3 main.py --file urls.txt --json
"""
    )
    parser.add_argument(
        "--url",
        metavar="URL",
        help="Check a single URL, e.g. --url https://example.com"
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a text file containing one URL per line"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result(s) as JSON instead of formatted text (useful for scripts)"
    )
    args = parser.parse_args()

    console.print("Loading model...", end=" ")
    model, scaler = load_artifacts()
    console.print("Ready!")

    if args.url:
        run_single(args.url, model, scaler, args.json)
    elif args.file:
        run_batch(args.file, model, scaler, args.json)
    else:
        run_interactive(model, scaler)


if __name__ == '__main__':
    main()
