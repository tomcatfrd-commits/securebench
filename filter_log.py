from pathlib import Path


INPUT = Path("ra-output.txt")
OUTPUT = Path("ra-output_relevant.txt")


def read_text_file(path: Path) -> str:
    """
    Read a text file while allowing Python to detect common
    Unicode BOMs automatically.

    utf-8-sig:
        UTF-8 with BOM

    utf-16:
        UTF-16 with BOM, including UTF-16 LE/BE
    """

    raw = path.read_bytes()

    # UTF-16 LE / BE BOM
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")

    # UTF-8 BOM
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")

    # Normal UTF-8
    return raw.decode("utf-8")


def find_line(lines: list[str], text: str) -> int:
    """Return the first line containing text, or -1."""

    text = text.lower()

    for index, line in enumerate(lines):
        if text in line.lower():
            return index

    return -1


def main() -> None:
    if not INPUT.exists():
        print(f"Input file does not exist: {INPUT.resolve()}")
        return

    text = read_text_file(INPUT)
    lines = text.splitlines()

    print(f"Input file    : {INPUT.resolve()}")
    print(f"Original lines: {len(lines):,}")

    # ---------------------------------------------------------
    # Find pytest FAILURES section
    # ---------------------------------------------------------

    failures_index = find_line(lines, "FAILURES")

    if failures_index == -1:
        print("Could not find the pytest FAILURES section.")
        return

    print(f"FAILURES line : {failures_index + 1:,}")

    # ---------------------------------------------------------
    # Find pytest short test summary
    # ---------------------------------------------------------

    summary_index = find_line(
        lines,
        "short test summary info",
    )

    if summary_index == -1:
        print("Could not find the short test summary.")

        # Preserve everything from FAILURES onward.
        summary_index = len(lines)

    else:
        print(f"Summary line  : {summary_index + 1:,}")

    # ---------------------------------------------------------
    # Build output
    #
    # Keep:
    #
    #   pytest session information
    #   complete FAILURES section
    #   short test summary
    #
    # Drop:
    #
    #   repetitive test progress lines
    # ---------------------------------------------------------

    output = []

    # Session header
    output.extend(lines[:failures_index])

    # Separator
    output.append("")
    output.append(
        "================== RELEVANT PYTEST OUTPUT =================="
    )
    output.append("")

    # Complete failure information
    output.extend(lines[failures_index:summary_index])

    # Summary
    if summary_index < len(lines):
        output.append("")
        output.append(
            "================== SHORT TEST SUMMARY =================="
        )
        output.append("")

        output.extend(lines[summary_index:])

    # ---------------------------------------------------------
    # Remove excessive blank lines.
    # ---------------------------------------------------------

    cleaned = []

    previous_blank = False

    for line in output:

        if not line.strip():

            if previous_blank:
                continue

            previous_blank = True
            cleaned.append("")

        else:

            previous_blank = False
            cleaned.append(line)

    # ---------------------------------------------------------
    # Write UTF-8 output.
    #
    # The original file remains untouched.
    # ---------------------------------------------------------

    OUTPUT.write_text(
        "\n".join(cleaned) + "\n",
        encoding="utf-8",
    )

    reduction = (
        1 - len(cleaned) / len(lines)
    ) * 100

    print(f"Output lines  : {len(cleaned):,}")
    print(f"Reduction     : {reduction:.1f}%")
    print(f"Output file   : {OUTPUT.resolve()}")


if __name__ == "__main__":
    main()