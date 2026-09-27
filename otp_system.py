"""
OTP Generator & Verifier
Task 5 -- AVIP 2026 Cybersecurity Track (B.Y.T.E by Arithmatrix)

A time-based one-time password (TOTP) system built from RFC 6238 / RFC 4226
principles using only the Python standard library (hmac, hashlib, struct,
base64) -- no third-party OTP libraries.

Usage:
    python otp_system.py
    (interactive menu -- generate a demo secret, generate OTPs, verify OTPs)

    python otp_system.py --demo
    (non-interactive -- runs a scripted demonstration and prints test vectors)
"""

import hmac
import hashlib
import struct
import time
import base64
import os
import argparse

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
CONFIG = {
    "otp_length": 6,            # number of digits in the OTP
    "time_step_seconds": 30,    # validity window per OTP (RFC 6238 default)
    "verification_window": 1,   # allow +/- N steps either side to tolerate clock drift
}


def generate_secret(length: int = 16) -> str:
    """Generates a random Base32-encoded secret suitable for TOTP use."""
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode("utf-8")


def _hotp(secret: str, counter: int, digits: int) -> str:
    """
    Core HOTP algorithm (RFC 4226): derives a `digits`-length numeric code
    from `secret` and `counter` using HMAC-SHA1. TOTP (below) simply feeds
    this a counter derived from the current time instead of an event count.
    """
    padded_secret = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret)
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code_bytes = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", code_bytes)[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def generate_otp(secret: str, for_time: float = None) -> str:
    """Generates the time-based OTP for `secret` valid at `for_time` (default: now)."""
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // CONFIG["time_step_seconds"])
    return _hotp(secret, counter, CONFIG["otp_length"])


def verify_otp(secret: str, submitted_otp: str, for_time: float = None) -> dict:
    """
    Verifies `submitted_otp` against `secret`. Checks the current time step
    plus CONFIG["verification_window"] steps before/after it, so an OTP
    generated a few seconds ago (or on a slightly-off clock) still verifies.
    Uses constant-time comparison to avoid timing side-channels.
    """
    if for_time is None:
        for_time = time.time()
    current_counter = int(for_time // CONFIG["time_step_seconds"])
    window = CONFIG["verification_window"]

    for offset in range(-window, window + 1):
        candidate = _hotp(secret, current_counter + offset, CONFIG["otp_length"])
        if hmac.compare_digest(candidate, submitted_otp):
            return {
                "valid": True,
                "matched_offset_steps": offset,
                "message": f"OTP VALID (matched at offset {offset:+d} time step).",
            }

    return {
        "valid": False,
        "matched_offset_steps": None,
        "message": "OTP INVALID or expired.",
    }


def run_demo():
    """Non-interactive scripted walkthrough -- used for the README demo output."""
    secret = "JBSWY3DPEHPK3PXP"  # fixed demo secret so output is reproducible
    print("=== OTP Generator & Verifier -- scripted demo ===")
    print(f"Demo secret (Base32): {secret}")
    print(f"Time step: {CONFIG['time_step_seconds']}s | OTP length: {CONFIG['otp_length']} digits")
    print(f"Verification window: +/-{CONFIG['verification_window']} step(s)\n")

    fixed_time = 1893456000.0  # fixed reference timestamp for reproducibility
    current_otp = generate_otp(secret, for_time=fixed_time)
    print(f"[Generate] OTP at reference time: {current_otp}")

    print(f"\n[Verify]  Correct OTP submitted immediately  -> ", end="")
    print(verify_otp(secret, current_otp, for_time=fixed_time)["message"])

    drifted_time = fixed_time + CONFIG["time_step_seconds"]
    print(f"[Verify]  Same OTP submitted one step later  -> ", end="")
    print(verify_otp(secret, current_otp, for_time=drifted_time)["message"])

    far_future = fixed_time + (5 * CONFIG["time_step_seconds"])
    print(f"[Verify]  Same OTP submitted 5 steps later    -> ", end="")
    print(verify_otp(secret, current_otp, for_time=far_future)["message"])

    print(f"[Verify]  Random incorrect OTP '000000'       -> ", end="")
    print(verify_otp(secret, "000000", for_time=fixed_time)["message"])


def run_interactive():
    print("=== OTP Generator & Verifier ===")
    secret = generate_secret()
    print(f"Generated demo secret (Base32): {secret}")
    print(f"Time step: {CONFIG['time_step_seconds']}s | OTP length: {CONFIG['otp_length']} digits\n")

    while True:
        print("1) Generate current OTP")
        print("2) Verify an OTP")
        print("3) Quit")
        try:
            choice = input("Choose an option: ").strip()
        except EOFError:
            break

        if choice == "1":
            otp = generate_otp(secret)
            print(f"Current OTP: {otp}  (valid for up to {CONFIG['time_step_seconds']}s)\n")
        elif choice == "2":
            submitted = input("Enter OTP to verify: ").strip()
            result = verify_otp(secret, submitted)
            print(result["message"], "\n")
        elif choice == "3":
            break
        else:
            print("Invalid option.\n")


def main():
    parser = argparse.ArgumentParser(description="TOTP-style OTP generator and verifier.")
    parser.add_argument("--demo", action="store_true", help="Run a scripted, reproducible demonstration.")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        run_interactive()


if __name__ == "__main__":
    main()
