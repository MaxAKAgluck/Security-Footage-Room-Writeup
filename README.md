
# Security Footage Room Writeup

## Description

> "Someone broke into our office last night, but they destroyed the hard drives with the security footage. Can you recover the footage?"

> **Note:** If you are using the AttackBox, you can find the task files inside the `/root/Rooms/securityfootage/` directory.

---

We are given a pcap file:

<img width="2088" height="603" alt="image" src="https://github.com/user-attachments/assets/dfe712eb-e380-459d-b842-be1d749c3ab7" />

After examining it for a while I saw that there are individual JFIF images transferred:

<img width="1146" height="368" alt="image" src="https://github.com/user-attachments/assets/8d285e87-b5c6-45ab-a69e-bac0f0adec6d" />

I then realised that we needed to gather the raw data and searched for magic bytes to identify how we could extract these raw images.

[This website](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5) provided a great deal of info — I now knew JFIF JPEG starts with `FFD8FF` and when I scrolled down in the raw packet we see:

<img width="829" height="216" alt="image" src="https://github.com/user-attachments/assets/f13039a7-6e03-4cdc-ba76-7076bb2c3e41" />

Which means those images end with `FFD9` bytes.

I then used Cursor to generate a script for me for extracting those images:

<img width="884" height="404" alt="image" src="https://github.com/user-attachments/assets/07f44d1b-416b-46ab-8a98-1e6156281eb0" />

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path


DEFAULT_INPUT = "security-footage-1648933966395.pcap"
DEFAULT_OUTPUT_DIR = "pcap_img"
JPEG_START = b"\xFF\xD8\xFF"
JPEG_END = b"\xFF\xD9"


def extract_jpegs(input_path: Path, output_dir: Path) -> int:
    data = input_path.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    search_from = 0

    while True:
        start = data.find(JPEG_START, search_from)
        if start == -1:
            break

        end = data.find(JPEG_END, start + len(JPEG_START))
        if end == -1:
            break

        count += 1
        image_bytes = data[start : end + len(JPEG_END)]
        output_path = output_dir / f"image_{count:04d}.jpg"
        output_path.write_bytes(image_bytes)

        search_from = end + len(JPEG_END)

    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract JPEG images from raw PCAP data using magic bytes."
    )
    parser.add_argument(
        "-i",
        "--input",
        default=DEFAULT_INPUT,
        help=f"Path to the input PCAP file (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to store extracted images (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output)

    if not input_path.is_file():
        raise SystemExit(f"Input file not found: {input_path}")

    extracted = extract_jpegs(input_path, output_dir)

    if extracted == 0:
        print("No JPEG images found.")
        return

    print(f"Extracted {extracted} image(s) to '{output_dir}'.")


if __name__ == "__main__":
    main()
```

Running the code produced 540 images and we can simply examine them one by one or scroll through them in the image editor of your choice, recover the flag:

<img width="335" height="263" alt="image" src="https://github.com/user-attachments/assets/7e9e3e10-fe9b-4f44-9c8b-2c0940818640" />

---

This was a very fast but intriguing room. I feel like if I let Cursor examine the file, Opus 4.6 would've cracked this case easily — Anthropic models are excellent for CTF-like challenges (and not only for them). There is an interesting article about this: [CTF is dying because of AI](https://blog.krauq.com/post/ctf-is-dying-because-of-ai).
