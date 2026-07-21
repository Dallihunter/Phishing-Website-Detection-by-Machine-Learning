"""
screenshot_quality_filter.py — cheap, local pre-filter for reference-capture
screenshots, so a large brand batch doesn't require a manual look at every
single render before anything gets hashed.

Catches ONE specific failure mode: a near-solid-color image (blank white/
black page, a loading spinner sitting on a flat background, a bare page
shell with no content painted in). That covers most of what we saw fail
during Iranian-fintech reference capture before allow_javascript=True was
added to visual_similarity.py. It does NOT catch text-based rejects
("access denied", CAPTCHA, wrong-locale redirect) — that needs OCR, which
isn't installed in this environment (tesseract-ocr requires a sudo install
this session didn't do). Anything that PASSES this filter still needs a
real look before being trusted — this only shrinks the pile, it doesn't
replace review.

Threshold calibration (see conversation history for the numbers): real,
approved reference screenshots measured 12.0-119.7 on BLANK_STDDEV_SCORE;
known blank/spinner failures measured 0.0-1.35. BLANK_STDDEV_THRESHOLD=5.0
sits with wide margin on both sides of that gap — same spirit as how
MATCH_THRESHOLD was picked for the hash-distance gap.
"""

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, ImageStat

BLANK_STDDEV_THRESHOLD = 5.0


def blank_score(image_bytes: bytes) -> float:
    """Average per-channel pixel stddev across R/G/B. Near 0 means the
    image is close to a single solid color — a blank page, a spinner on a
    flat background, or similar 'nothing really rendered' states. Real
    pages with actual layout/content score well above BLANK_STDDEV_THRESHOLD
    even when mostly white/sparse (see calibration note above)."""
    img = Image.open(BytesIO(image_bytes)).convert("RGB")
    stat = ImageStat.Stat(img)
    return sum(stat.stddev) / len(stat.stddev)


def is_likely_blank(image_bytes: bytes, threshold: float = BLANK_STDDEV_THRESHOLD) -> bool:
    return blank_score(image_bytes) < threshold


@dataclass
class FilterResult:
    brand: str
    url: str
    checked: bool                  # False = render itself failed (SSRF block, timeout, etc)
    unavailable_reason: str = None
    blank_score_value: float = None
    likely_blank: bool = None      # None if checked is False
    screenshot_path: str = None    # where the PNG was saved, if any


async def capture_and_filter(brands: dict, out_dir: str, settle_ms: int = 4000) -> list:
    """Renders each brand's URL (JS enabled — see visual_similarity.py's
    allow_javascript docstring for why this is safe only for a curated,
    human-picked URL list like this one), scores it, and saves the PNG
    regardless of the verdict so a human can still override the filter.
    Returns a list of FilterResult, most-suspicious first, so review time
    goes to the ones the filter is least confident about.
    """
    import visual_similarity as vs

    results = []
    for brand, url in brands.items():
        try:
            check = await vs.check_visual_similarity(
                url, include_screenshot=True, settle_ms=settle_ms, allow_javascript=True
            )
        except Exception as e:
            results.append(FilterResult(brand=brand, url=url, checked=False,
                                         unavailable_reason=f"exception: {e!r}"))
            continue

        if not check.checked:
            results.append(FilterResult(brand=brand, url=url, checked=False,
                                         unavailable_reason=check.unavailable_reason))
            continue

        score = blank_score(check.screenshot_png)
        path = f"{out_dir}/{brand}.png"
        with open(path, "wb") as f:
            f.write(check.screenshot_png)

        results.append(FilterResult(
            brand=brand, url=url, checked=True,
            blank_score_value=score, likely_blank=score < BLANK_STDDEV_THRESHOLD,
            screenshot_path=path,
        ))

    results.sort(key=lambda r: (r.checked, r.blank_score_value if r.blank_score_value is not None else -1))
    return results


def print_report(results: list) -> None:
    likely_blank = [r for r in results if r.checked and r.likely_blank]
    passed = [r for r in results if r.checked and not r.likely_blank]
    failed = [r for r in results if not r.checked]

    print(f"\n{'='*60}")
    print(f"AUTO-REJECTED (likely blank, score < {BLANK_STDDEV_THRESHOLD}) — {len(likely_blank)}")
    print(f"{'='*60}")
    for r in likely_blank:
        print(f"  {r.brand:20} score={r.blank_score_value:.2f}  {r.url}")

    print(f"\n{'='*60}")
    print(f"RENDER FAILED (SSRF block / timeout / error) — {len(failed)}")
    print(f"{'='*60}")
    for r in failed:
        print(f"  {r.brand:20} {r.unavailable_reason}  {r.url}")

    print(f"\n{'='*60}")
    print(f"NEEDS HUMAN REVIEW (passed blank-filter) — {len(passed)}")
    print(f"{'='*60}")
    for r in passed:
        print(f"  {r.brand:20} score={r.blank_score_value:.2f}  {r.screenshot_path}")
