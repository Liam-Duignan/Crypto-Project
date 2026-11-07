"""Builds the report tables (median and IQR, in milliseconds) from raw.csv.

Usage:  python make_tables.py results/run-1
Prints the tables and also saves them to results/run-1/tables.md
"""

import csv
import math
import os
import statistics
import sys


def sig(x):
    """Format a number to 3 significant figures without scientific notation."""
    if x == 0:
        return "0"
    digits = 3 - int(math.floor(math.log10(abs(x)))) - 1
    digits = max(digits, 0)
    return f"{round(x, digits):.{digits}f}"


def read_runs(path):
    """Return {(part, algorithm, operation, message_bytes): [times in ms]},
    leaving out run 0 (the warm-up)."""
    data = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if int(row["run"]) == 0:
                continue
            key = (
                row["part"],
                row["algorithm"],
                row["operation"],
                int(row["message_bytes"]),
            )
            data.setdefault(key, []).append(int(row["nanoseconds"]) / 1_000_000)
    return data


def median_and_iqr(times):
    q1, _, q3 = statistics.quantiles(times, n=4)
    return statistics.median(times), q3 - q1


def markdown_table(first_header, operations, rows):
    """rows is a list of (label, {operation: (median, iqr)})."""
    header = f"| {first_header} |"
    divider = "|---|"
    sub = "| |"
    for op in operations:
        header += f" {op} | |"
        divider += "---|---|"
        sub += " Median | IQR |"
    lines = [header, sub, divider]
    for label, results in rows:
        line = f"| {label} |"
        for op in operations:
            median, iqr = results[op]
            line += f" {sig(median)} | {sig(iqr)} |"
        lines.append(line)
    return "\n".join(lines)


def build_table(data, part, operations, with_length=False):
    """Collect one row per algorithm (or per algorithm and message length)."""
    rows = []
    seen = []
    for (p, algorithm, operation, length) in data:
        if p != part:
            continue
        label_key = (algorithm, length) if with_length else algorithm
        if label_key not in seen:
            seen.append(label_key)

    for label_key in seen:
        results = {}
        for op in operations:
            if with_length:
                algorithm, length = label_key
                times = data[(part, algorithm, op, length)]
                label = f"{algorithm}, {length} B"
            else:
                times = data[(part, label_key, op, 0)]
                label = label_key
            results[op] = median_and_iqr(times)
        rows.append((label, results))

    first_header = "Algorithm, message length" if with_length else "Algorithm"
    return markdown_table(first_header, operations, rows)


def main():
    if len(sys.argv) != 2:
        print("usage: python make_tables.py results/run-1")
        sys.exit(1)

    run_dir = sys.argv[1]
    data = read_runs(os.path.join(run_dir, "raw.csv"))

    output = []
    output.append("Key establishment (ms)\n")
    output.append(build_table(data, "kem", ["keygen", "encapsulate", "decapsulate"]))
    output.append("\nDigital signatures (ms)\n")
    output.append(build_table(data, "signature", ["keygen", "sign", "verify"]))
    output.append("\nAuthenticated encryption (ms)\n")
    output.append(build_table(data, "aead", ["encrypt", "decrypt"], with_length=True))
    text = "\n".join(output) + "\n"

    print(text)
    with open(os.path.join(run_dir, "tables.md"), "w") as f:
        f.write(text)
    print("saved:", os.path.join(run_dir, "tables.md"))


if __name__ == "__main__":
    main()