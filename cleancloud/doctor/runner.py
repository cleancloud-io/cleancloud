"""
Enterprise-grade doctor runner with proper error handling and summary reporting.
"""

import sys
from typing import Optional

from cleancloud.doctor.aws import run_aws_doctor
from cleancloud.doctor.azure import run_azure_doctor
from cleancloud.doctor.common import DoctorError, info, success


def run_doctor(
    provider: Optional[str] = None, profile: Optional[str] = None, region: Optional[str] = None
) -> None:
    """
    Run health checks for cloud provider credentials and permissions.

    Provides enterprise-grade diagnostics suitable for security audits
    and acquirer due diligence.

    Args:
        provider: Cloud provider to check ("aws", "azure", or None for both)
        profile: AWS profile name (optional)
        region: AWS region (optional, defaults to us-east-1)

    Exit codes:
        0: All checks passed
        1: Unexpected error
        3: Doctor check failed (credentials or permissions)
    """

    # Validate provider
    valid_providers = ["aws", "azure"]
    if provider is not None and provider not in valid_providers:
        info("")
        print(f"❌ Invalid provider: {provider}")
        info("")
        info(f"Valid providers: {', '.join(valid_providers)}")
        info("Or omit --provider to check both")
        info("")
        sys.exit(1)

    # Determine which providers to check
    providers_to_check = []
    if provider is None:
        providers_to_check = ["aws", "azure"]
    else:
        providers_to_check = [provider]

    # Track results
    results = {}

    # Main header
    info("")
    info("=" * 70)
    info("CLEANCLOUD ENVIRONMENT DIAGNOSTICS")
    info("=" * 70)
    info("")
    info(f"Providers to check: {', '.join(p.upper() for p in providers_to_check)}")
    info("")

    # Run checks for each provider
    for p in providers_to_check:
        try:
            if p == "aws":
                run_aws_doctor(profile=profile, region=region or "us-east-1")
                results[p] = {"status": "passed", "error": None}

            elif p == "azure":
                run_azure_doctor()
                results[p] = {"status": "passed", "error": None}

        except DoctorError as e:
            # Doctor check failed (expected failure with nice error message)
            results[p] = {"status": "failed", "error": str(e)}

            # If only checking one provider, exit immediately
            if len(providers_to_check) == 1:
                sys.exit(3)

            # Otherwise, continue to next provider
            info("")
            info(f"⚠️  {p.upper()} validation failed, continuing to next provider...")
            info("")

        except Exception as e:
            # Unexpected error
            results[p] = {"status": "error", "error": str(e)}
            info("")
            print(f"❌ Unexpected error validating {p.upper()}: {e}")
            info("")

            # If only checking one provider, exit immediately
            if len(providers_to_check) == 1:
                sys.exit(1)

    # Print summary if checking multiple providers
    if len(providers_to_check) > 1:
        info("")
        info("=" * 70)
        info("FINAL SUMMARY")
        info("=" * 70)
        info("")

        all_passed = True

        for p in providers_to_check:
            result = results.get(p, {"status": "unknown", "error": "Not checked"})
            status = result["status"]

            if status == "passed":
                success(f"{p.upper()}: ✅ PASSED")
            elif status == "failed":
                # Don't use fail() here - it raises an exception!
                # Just print the status
                print(f"❌ {p.upper()}: ❌ FAILED")
                all_passed = False
                if result["error"]:
                    info(f"  Error: {result['error']}")
            else:
                print(f"❌ {p.upper()}: ⚠️  ERROR")
                all_passed = False
                if result["error"]:
                    info(f"  Error: {result['error']}")

        info("")
        info("=" * 70)

        if all_passed:
            info("")
            success("✅ ALL PROVIDERS VALIDATED SUCCESSFULLY")
            info("")
            sys.exit(0)
        else:
            info("")
            print("❌ SOME PROVIDERS FAILED VALIDATION")
            info("")
            info("Fix the errors above and re-run `cleancloud doctor`")
            info("")
            sys.exit(3)
