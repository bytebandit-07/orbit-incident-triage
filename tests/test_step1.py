import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.data_loader import get_loader

def run_tests():
    loader = get_loader()
    report = loader.preload_all()

    print("=== PRELOAD TEST REPORT ===")
    print(f"Total files loaded: {len(report.loaded)} of 20")
    print(f"Missing files: {report.missing}")
    print(f"Errors: {report.errors}")
    if report.warnings:
        print("Warnings:")
        for f, w in report.warnings.items():
            print(f"  {f}: {w}")

    print("\n=== CITATION & DATA EXTRACTION CHECKS ===")
    # Test 1: Log line 1 of VPN log
    line1 = loader.get_log_line("11_vpn_auth_log.md", 1)
    print(f"11_vpn_auth_log.md:1 -> {line1[:60]}...")

    # Test 2: Asset inventory lookup
    row_asset = loader.get_row("02_asset_inventory.md", "A-1001")
    print(f"A-1001 Hostname -> {row_asset.get('Hostname')} ({row_asset.get('Criticality')})")

    # Test 3: Change calendar lookup
    row_chg = loader.get_row("05_change_calendar.md", "CHG-2026-1104-02")
    print(f"CHG-02 -> {row_chg.get('Description')}")

    # Test 4: Runbook step lookup
    step1 = loader.get_runbook_step("06_runbook_phishing.md", 1)
    print(f"Phishing Step 1 -> {step1.text[:60]}...")

    # Test 5: Citation verification
    c1 = loader.verify_citation("11_vpn_auth_log.md:8")
    c2 = loader.verify_citation("02_asset_inventory.md:A-1005")
    c3 = loader.verify_citation("11_vpn_auth_log.md:999") # should fail
    print(f"Citation check 11_vpn_auth_log.md:8: {c1.valid}")
    print(f"Citation check 02_asset_inventory.md:A-1005: {c2.valid}")
    print(f"Citation check 11_vpn_auth_log.md:999 (invalid): {c3.valid} ({c3.reason})")

    if len(report.loaded) == 20 and not report.errors and c1.valid and not c3.valid:
        print("\n>>> ALL STEP 1 BACKEND TESTS PASSED SUCCESSFULLY (20/20 FILES)! <<<")
        return True
    return False

if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
