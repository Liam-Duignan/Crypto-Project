"""Makes the three plots for one run from raw.csv.

Usage:  python make_plots.py results/run-1
Needs:  pip install matplotlib
Saves kem.png, signature.png and aead.png in the run directory.
"""

import os
import statistics
import sys

import matplotlib

matplotlib.use("Agg")  # lets it save images without a display (e.g. Codespaces)
import matplotlib.pyplot as plt

from make_tables import read_runs  # reuses the reader that skips run 0


def bar_plot(data, part, operations, title, path):
    """Grouped bars: algorithms on the x-axis, one bar per operation, log y-axis."""
    algorithms = []
    for (p, algorithm, operation, length) in data:
        if p == part and algorithm not in algorithms:
            algorithms.append(algorithm)

    width = 0.8 / len(operations)
    fig, ax = plt.subplots(figsize=(10, 5))

    for i, op in enumerate(operations):
        positions = [x + (i - (len(operations) - 1) / 2) * width
                     for x in range(len(algorithms))]
        medians = [statistics.median(data[(part, a, op, 0)]) for a in algorithms]
        ax.bar(positions, medians, width, label=op)

    ax.set_yscale("log")
    ax.set_xticks(range(len(algorithms)))
    ax.set_xticklabels(algorithms, rotation=30, ha="right")
    ax.set_xlabel("Algorithm")
    ax.set_ylabel("Time (ms)")
    ax.set_title(title)
    ax.legend()
    ax.grid(axis="y", which="major", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    print("saved:", path)


def aead_plot(data, path):
    """Median encrypt time against message length, one line per algorithm,
    both axes logarithmic."""
    algorithms = []
    for (p, algorithm, operation, length) in data:
        if p == "aead" and algorithm not in algorithms:
            algorithms.append(algorithm)

    fig, ax = plt.subplots(figsize=(8, 5))
    for algorithm in algorithms:
        lengths = sorted(
            length for (p, a, op, length) in data
            if p == "aead" and a == algorithm and op == "encrypt"
        )
        medians = [
            statistics.median(data[("aead", algorithm, "encrypt", length)])
            for length in lengths
        ]
        ax.plot(lengths, medians, marker="o", label=algorithm)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Message length (bytes)")
    ax.set_ylabel("Median encrypt time (ms)")
    ax.set_title("Authenticated encryption: encrypt time vs message length")
    ax.legend()
    ax.grid(which="major", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    print("saved:", path)


def main():
    if len(sys.argv) != 2:
        print("usage: python make_plots.py results/run-1")
        sys.exit(1)

    run_dir = sys.argv[1]
    data = read_runs(os.path.join(run_dir, "raw.csv"))

    bar_plot(data, "kem", ["keygen", "encapsulate", "decapsulate"],
             "Key establishment: median time per operation",
             os.path.join(run_dir, "kem.png"))
    bar_plot(data, "signature", ["keygen", "sign", "verify"],
             "Digital signatures: median time per operation",
             os.path.join(run_dir, "signature.png"))
    aead_plot(data, os.path.join(run_dir, "aead.png"))


if __name__ == "__main__":
    main()