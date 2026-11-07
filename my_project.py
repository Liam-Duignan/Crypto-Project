"""CryptoBench: times key establishment, signatures and authenticated
encryption with pyca/cryptography (version 50 or later).

Usage:  python my_project.py results/run-1
"""

import csv
import os
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA65PrivateKey,
    MLDSA87PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM1024PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    ChaCha20Poly1305,
)

RUNS = 101         # run 0 is the warm-up
RSA_KEYGEN_RUNS = 21
MESSAGE_LENGTHS = [64, 1024, 16384, 1048576]


# ---------------------------------------------------------------- helpers

def time_call(func, *args):
    """Time one call of func(*args) in nanoseconds."""
    start = time.perf_counter_ns()
    func(*args)
    end = time.perf_counter_ns()
    return end - start


def measure(writer, part, algorithm, operation, message_bytes, func, runs=RUNS):
    """Run func `runs` times, timing each run, and write every run to raw.csv."""
    for run in range(runs):
        ns = time_call(func)
        writer.writerow([part, algorithm, operation, message_bytes, run, ns])
    print(f"done: {part} {algorithm} {operation} {message_bytes}")


# ---------------------------------------------------------- key establishment

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def benchmark_rsa_oaep(writer, bits):
    name = f"RSA-OAEP-{bits}"

    def keygen():
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    # key pair for the other operations (outside the timing)
    private_key = keygen()
    public_key = private_key.public_key()

    def encapsulate():
        secret = os.urandom(32)
        return public_key.encrypt(secret, OAEP)

    ciphertext = encapsulate()  # produced before the clock starts

    def decapsulate():
        return private_key.decrypt(ciphertext, OAEP)

    measure(writer, "kem", name, "keygen", 0, keygen, RSA_KEYGEN_RUNS)
    measure(writer, "kem", name, "encapsulate", 0, encapsulate)
    measure(writer, "kem", name, "decapsulate", 0, decapsulate)


def benchmark_ecdh(writer, name, curve):
    def keygen():
        return ec.generate_private_key(curve)

    private_key = keygen()
    public_key = private_key.public_key()

    def encapsulate():
        ephemeral = ec.generate_private_key(curve)
        ephemeral.exchange(ec.ECDH(), public_key)
        return ephemeral.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    ciphertext = encapsulate()

    def decapsulate():
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, ciphertext
        )
        return private_key.exchange(ec.ECDH(), ephemeral_public)

    measure(writer, "kem", name, "keygen", 0, keygen)
    measure(writer, "kem", name, "encapsulate", 0, encapsulate)
    measure(writer, "kem", name, "decapsulate", 0, decapsulate)


def benchmark_x25519(writer):
    name = "X25519"

    def keygen():
        return X25519PrivateKey.generate()

    private_key = keygen()
    public_key = private_key.public_key()

    def encapsulate():
        ephemeral = X25519PrivateKey.generate()
        ephemeral.exchange(public_key)
        return ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    ciphertext = encapsulate()

    def decapsulate():
        ephemeral_public = X25519PublicKey.from_public_bytes(ciphertext)
        return private_key.exchange(ephemeral_public)

    measure(writer, "kem", name, "keygen", 0, keygen)
    measure(writer, "kem", name, "encapsulate", 0, encapsulate)
    measure(writer, "kem", name, "decapsulate", 0, decapsulate)


def benchmark_mlkem(writer, name, key_class):
    def keygen():
        return key_class.generate()

    private_key = keygen()
    public_key = private_key.public_key()

    def encapsulate():
        return public_key.encapsulate()  # returns (shared_secret, ciphertext)

    _, ciphertext = encapsulate()

    def decapsulate():
        return private_key.decapsulate(ciphertext)

    measure(writer, "kem", name, "keygen", 0, keygen)
    measure(writer, "kem", name, "encapsulate", 0, encapsulate)
    measure(writer, "kem", name, "decapsulate", 0, decapsulate)


# ------------------------------------------------------------ digital signatures

def benchmark_rsa_pss(writer, bits, message):
    name = f"RSA-PSS-{bits}"
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    )

    def keygen():
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    private_key = keygen()
    public_key = private_key.public_key()

    def sign():
        return private_key.sign(message, pss, hashes.SHA256())

    signature = sign()

    def verify():
        public_key.verify(signature, message, pss, hashes.SHA256())

    measure(writer, "signature", name, "keygen", 0, keygen, RSA_KEYGEN_RUNS)
    measure(writer, "signature", name, "sign", 0, sign)
    measure(writer, "signature", name, "verify", 0, verify)


def benchmark_ecdsa(writer, name, curve, hash_algorithm, message):
    def keygen():
        return ec.generate_private_key(curve)

    private_key = keygen()
    public_key = private_key.public_key()

    def sign():
        return private_key.sign(message, ec.ECDSA(hash_algorithm))

    signature = sign()

    def verify():
        public_key.verify(signature, message, ec.ECDSA(hash_algorithm))

    measure(writer, "signature", name, "keygen", 0, keygen)
    measure(writer, "signature", name, "sign", 0, sign)
    measure(writer, "signature", name, "verify", 0, verify)


def benchmark_direct_signature(writer, name, key_class, message):
    """Ed25519 and ML-DSA: the message is passed directly to the key."""

    def keygen():
        return key_class.generate()

    private_key = keygen()
    public_key = private_key.public_key()

    def sign():
        return private_key.sign(message)

    signature = sign()

    def verify():
        public_key.verify(signature, message)

    measure(writer, "signature", name, "keygen", 0, keygen)
    measure(writer, "signature", name, "sign", 0, sign)
    measure(writer, "signature", name, "verify", 0, verify)


# ------------------------------------------------------- authenticated encryption

def benchmark_aead(writer, name, cipher_class, key_length, length):
    key = os.urandom(key_length)
    message = os.urandom(length)
    cipher = cipher_class(key)

    # encrypt: a fresh random nonce each run, generated before the clock starts
    for run in range(RUNS):
        nonce = os.urandom(12)
        ns = time_call(cipher.encrypt, nonce, message, None)
        writer.writerow(["aead", name, "encrypt", length, run, ns])

    # decrypt: the same ciphertext every run, produced before the clock starts
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, message, None)
    for run in range(RUNS):
        ns = time_call(cipher.decrypt, nonce, ciphertext, None)
        writer.writerow(["aead", name, "decrypt", length, run, ns])

    print(f"done: aead {name} {length}")


# ------------------------------------------------------------------------ main

def main():
    if len(sys.argv) != 2:
        print("usage: python my_project.py results/run-1")
        sys.exit(1)

    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "raw.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["part", "algorithm", "operation", "message_bytes", "run", "nanoseconds"]
        )

        # ---- Part 1: key establishment (Table 1)
        benchmark_rsa_oaep(writer, 3072)
        benchmark_rsa_oaep(writer, 7680)
        benchmark_ecdh(writer, "ECDH-P-256", ec.SECP256R1())
        benchmark_ecdh(writer, "ECDH-P-384", ec.SECP384R1())
        benchmark_ecdh(writer, "ECDH-P-521", ec.SECP521R1())
        benchmark_x25519(writer)
        benchmark_mlkem(writer, "ML-KEM-768", MLKEM768PrivateKey)
        benchmark_mlkem(writer, "ML-KEM-1024", MLKEM1024PrivateKey)

        # ---- Part 2: digital signatures (Table 2)
        message = os.urandom(1024)  # one random 1 KiB message for everything
        benchmark_rsa_pss(writer, 3072, message)
        benchmark_rsa_pss(writer, 7680, message)
        benchmark_ecdsa(writer, "ECDSA-P-256", ec.SECP256R1(), hashes.SHA256(), message)
        benchmark_ecdsa(writer, "ECDSA-P-384", ec.SECP384R1(), hashes.SHA384(), message)
        benchmark_ecdsa(writer, "ECDSA-P-521", ec.SECP521R1(), hashes.SHA512(), message)
        benchmark_direct_signature(writer, "Ed25519", Ed25519PrivateKey, message)
        benchmark_direct_signature(writer, "ML-DSA-44", MLDSA44PrivateKey, message)
        benchmark_direct_signature(writer, "ML-DSA-65", MLDSA65PrivateKey, message)
        benchmark_direct_signature(writer, "ML-DSA-87", MLDSA87PrivateKey, message)

        # ---- Part 3: authenticated encryption (Table 3)
        aead_algorithms = [
            ("AES-128-GCM", AESGCM, 16),
            ("AES-256-GCM", AESGCM, 32),
            ("ChaCha20-Poly1305", ChaCha20Poly1305, 32),
            ("AES-256-GCM-SIV", AESGCMSIV, 32),
        ]
        for name, cipher_class, key_length in aead_algorithms:
            for length in MESSAGE_LENGTHS:
                benchmark_aead(writer, name, cipher_class, key_length, length)

    print("finished: wrote", os.path.join(out_dir, "raw.csv"))


if __name__ == "__main__":
    main()