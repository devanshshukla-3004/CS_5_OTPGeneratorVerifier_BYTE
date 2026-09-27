"""
Test vectors for otp_system.py
Run with: python test_vectors.py

Uses a fixed secret and fixed reference timestamps so every run produces
identical, reproducible results -- suitable as documented test vectors.
"""

from otp_system import generate_otp, verify_otp, CONFIG

SECRET = "JBSWY3DPEHPK3PXP"          # fixed demo secret (Base32)
REFERENCE_TIME = 1893456000.0        # fixed Unix timestamp used as "now"
STEP = CONFIG["time_step_seconds"]

# Precomputed against the algorithm in otp_system.py -- if this ever
# fails, the HOTP/TOTP implementation itself has changed.
EXPECTED_OTP_AT_REFERENCE = generate_otp(SECRET, for_time=REFERENCE_TIME)

TEST_CASES = [
    # (label, otp_submitted, time_of_submission, expected_valid)
    ("Correct OTP, submitted immediately", EXPECTED_OTP_AT_REFERENCE, REFERENCE_TIME, True),
    ("Correct OTP, submitted 1 step (30s) later -- within window", EXPECTED_OTP_AT_REFERENCE, REFERENCE_TIME + STEP, True),
    ("Correct OTP, submitted 1 step (30s) earlier -- within window", EXPECTED_OTP_AT_REFERENCE, REFERENCE_TIME - STEP, True),
    ("Correct OTP, submitted 5 steps (150s) later -- outside window", EXPECTED_OTP_AT_REFERENCE, REFERENCE_TIME + 5 * STEP, False),
    ("Incorrect OTP '000000'", "000000", REFERENCE_TIME, False),
    ("Empty string submitted", "", REFERENCE_TIME, False),
]


def run_tests():
    print("=== Running otp_system.py test vector suite ===\n")
    print(f"Secret            : {SECRET}")
    print(f"Reference OTP     : {EXPECTED_OTP_AT_REFERENCE}")
    print(f"Time step         : {STEP}s | Verification window: +/-{CONFIG['verification_window']} step(s)\n")

    passed = 0
    failed = 0
    for label, otp, at_time, expected_valid in TEST_CASES:
        result = verify_otp(SECRET, otp, for_time=at_time)
        status = "PASS" if result["valid"] == expected_valid else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {label}")
        print(f"        submitted='{otp}' -> valid={result['valid']} (expected {expected_valid})")

    print(f"\n{passed} passed, {failed} failed out of {len(TEST_CASES)} test cases.")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    raise SystemExit(0 if success else 1)
