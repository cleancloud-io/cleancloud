def print_human_readable(result: dict):
    print("\nCleanCloud Scan Results")
    print("=" * 25)
    print(f"Provider: {result['provider']}")
    print(f"Account:  {result['account_id']}")
    print(f"Region:   {result['region']}")
    print(f"Scan at:  {result['scan_time']}")
    print()

    findings = result.get("findings", [])
    if not findings:
        print("✅ No issues found.")
        return

    for f in findings:
        print(f"- [{f['confidence']}] {f['summary']}")
        print(f"  Rule: {f['rule_id']}")
        print(f"  Resource: {f['resource_id']}")
        print(f"  Risk: {f['risk']}")
        print()
