"""
Downloads the raw datasets required for training.
Run this once before feature_extractor.py / train_model.py.
"""

import zipfile
from pathlib import Path
import urllib.request

DATA_DIR = Path(__file__).resolve().parent / "Phishing URL dataset"

FILES = {
    
    "Phishing URLs.csv": "https://data.mendeley.com/public-files/datasets/vfszbj9b36/files/97e4b9fc-8c55-4579-ae80-d30740d00913/file_downloaded",
    "URL dataset.csv": "https://data.mendeley.com/public-files/datasets/vfszbj9b36/files/f0de314f-ea72-4385-9faa-f06593bb0a2d/file_downloaded",
    "phiusiil.zip": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
}


def download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  already exists, skipping: {dest.name}")
        return
    print(f"  downloading {dest.name} ...")
    urllib.request.urlretrieve(url, dest)


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)

    for filename, url in FILES.items():
        dest = DATA_DIR / filename
        download(url, dest)

    zip_path = DATA_DIR / "phiusiil.zip"
    if zip_path.exists():
        print("  extracting phiusiil.zip ...")
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(DATA_DIR)
        zip_path.unlink()

    print("Done. Dataset files are in:", DATA_DIR)


if __name__ == "__main__":
    main()
