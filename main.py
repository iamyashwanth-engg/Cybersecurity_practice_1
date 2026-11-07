import json
import cia_controls
import defense_control
import vulnerability_management

def main():
    print("=" * 60)
    print("STARTING SECURITY OPERATIONS & CONTROL SYSTEM (SOCS)")
    print("=" * 60)

    # ---------------------------------------------------------
    # SCENARIO 1: CONFIDENTIALITY & INTEGRITY (CIA TRIAD)
    # ---------------------------------------------------------

    print("\n[+] 1. TESTING CONFIDENTIALITY & INTEGRITY CONTROLS")
    secret_key = b"enterprise-hmac-secret-auth-key"
    enc_key = cia_controls.generate_encryption_key()

    record = "CONFIDENTIAL_PATIENT_MEDICAL_HISTORY_#4412"
    print(f"Original Text: {record}")

    # Confidentiality: Encrypt
    encrypted_record = cia_controls.encrypt_data(record, enc_key)
    print(f"Encrypted (Confidentiality): {encrypted_record[:40]}...")

    # Integrity: Sign
    valid_signature = cia_controls.sign_payload(record, secret_key)
    print(f"HMAC Signature (Integrity): {valid_signature}")

    # Validation: Clean check
    is_valid = cia_controls.verify_integrity(record, valid_signature, secret_key)
    print(f"Clean Payload Integrity Verified? -> {is_valid}")

    # Validation: Tamper check
    tampered_record = record + "; DROP USERS;"
    is_tampered_valid = cia_controls.verify_integrity(tampered_record, valid_signature, secret_key)
    print(f"Tampered Payload Integrity Verified? -> {is_tampered_valid}")
    if not is_tampered_valid:
        defense_control.log_security_event("WARNING", "Payload tampering identified in transit!")

    # ---------------------------------------------------------
    # SCENARIO 2: PREVENTIVE CONTROLS (ATTACK SURFACE REDUCTION)
    # ---------------------------------------------------------
    print("\n[+] 2. TESTING PREVENTIVE SECURITY CONTROLS")
    malicious_input = "admin' OR 1=1; DROP TABLE users; --"
    try:
        defense_control.sanitize_input(malicious_input)
    except ValueError as err:
        print(f"[BLOCKED] Preventive control stopped malicious input: {err}")

    # ---------------------------------------------------------
    # SCENARIO 3: AVAILABILITY & CORRECTIVE CONTROLS
    # ---------------------------------------------------------
    print("\n[+] 3. TESTING AVAILABILITY & AUTOMATED CORRECTIVE CONTROLS")
    attacker_ip = "198.51.100.44"

    for req_num in range(1, 6):
        allowed = cia_controls.check_rate_limit(attacker_ip)
        print(f"Request {req_num} from {attacker_ip} permitted? -> {allowed}")

        if not allowed:
            defense_control.log_security_event("WARNING", f"Rate limit reached for {attacker_ip}")
            # Trigger corrective action (automated isolation)
            defense_control.isolate_client(attacker_ip, "Exceeded DoS threshold")
            break

    # Verify if quarantine worked
    quarantined = defense_control.is_client_isolated(attacker_ip)
    print(f"Is {attacker_ip} successfully quarantined? -> {quarantined}")

    # ---------------------------------------------------------
    # SCENARIO 4: VULNERABILITY MANAGEMENT & CVSS CLASSIFICATION
    # ---------------------------------------------------------
    print("\n[+] 4. TESTING VULNERABILITY MANAGEMENT & CLASSIFICATION")
    findings = [
        ("Log4j Remote Code Execution (RCE)", 10.0, 10.0),
        ("Stored Cross-Site Scripting (XSS)", 5.5, 4.0),
        ("Missing HTTP Security Headers", 2.0, 1.5)
    ]

    for name, exploitability, impact in findings:
        report = vulnerability_management.generate_vulnerability_report(name, exploitability, impact)
        print(json.dumps(report, indent=2))

    print("\n" + "=" * 60)
    print("ALL SECURITY CONTROLS EVALUATED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()