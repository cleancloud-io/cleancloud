from typing import List

from cleancloud.core.finding import Finding


def print_human(findings: List[Finding]):
    if not findings:
        print("🎉 No hygiene issues detected")
        return

    print(f"\n🔍 Found {len(findings)} hygiene issues:\n")

    for i, f in enumerate(findings, start=1):
        print(f"{i}. [{f.provider.upper()}] {f.title}")

        print(f"   Risk       : {f.risk.value.capitalize()}")
        print(f"   Confidence : {f.confidence.value.capitalize()}")

        print(f"   Resource   : {f.resource_type} → {f.resource_id}")
        if f.region:
            print(f"   Region     : {f.region}")

        print(f"   Rule       : {f.rule_id}")
        print(f"   Reason     : {f.reason}")
        print(f"   Detected   : {f.detected_at.isoformat()}")

        if f.details:
            print("   Details:")
            for k, v in f.details.items():
                print(f"     - {k}: {v}")

        print()
