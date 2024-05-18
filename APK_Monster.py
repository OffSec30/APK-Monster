import zipfile
import re
import argparse
import json
import os
from termcolor import colored
from tqdm import tqdm
from androguard.misc import AnalyzeAPK

def extract_strings_from_files(apk_file):
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        apk_contents = zip_ref.namelist()
        strings = []

        for file in tqdm(apk_contents, desc="Extracting strings"):
            if file.endswith(".xml") or file.endswith(".arsc") or file.endswith(".txt") or file.endswith(".json"):
                with zip_ref.open(file) as f:
                    data = f.read().decode(errors='ignore')
                    strings.extend(re.findall(r'"([^"]*)"', data))
        
        return strings

def analyze_apk(apk_file):
    a, d, dx = AnalyzeAPK(apk_file)
    
    analysis_results = {
        "package_name": a.get_package(),
        "permissions": a.get_permissions(),
        "activities": a.get_activities(),
        "services": a.get_services(),
        "receivers": a.get_receivers(),
        "providers": a.get_providers(),
        "exported_activities": [activity for activity in a.get_activities() if a.get_intent_filters('activity', activity)],
        "exported_services": [service for service in a.get_services() if a.get_intent_filters('service', service)],
        "exported_receivers": [receiver for receiver in a.get_receivers() if a.get_intent_filters('receiver', receiver)],
        "exported_providers": [provider for provider in a.get_providers() if a.get_intent_filters('provider', provider)],
    }
    
    return analysis_results, d

def check_hardcoded_secrets(strings):
    secrets = [s for s in strings if re.search(r'password|token|key|secret|api', s, re.I)]
    return secrets

def check_insecure_permissions(permissions):
    insecure_permissions = [
        "android.permission.INTERNET",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ]
    return [perm for perm in permissions if perm in insecure_permissions]

def check_weak_cryptography(dex_files):
    weak_crypto_patterns = [
        "AES/ECB/PKCS5Padding",
        "DES",
        "DESede",
        "Blowfish",
    ]
    weak_crypto_uses = []
    
    for dex in dex_files:
        for class_def in dex.get_classes():
            class_name = class_def.get_name()
            for method in class_def.get_methods():
                code = method.get_code()
                if code:
                    bc = code.get_bc()
                    for instruction in bc.get_instructions():
                        if any(pattern in instruction.get_output() for pattern in weak_crypto_patterns):
                            weak_crypto_uses.append(f"Class: {class_name}, Method: {method.get_name()}, Instruction: {instruction.get_output()}")
    
    return weak_crypto_uses

def check_exported_components(analysis_results):
    exported_issues = {}
    if analysis_results["exported_activities"]:
        exported_issues["activities"] = analysis_results["exported_activities"]
    if analysis_results["exported_services"]:
        exported_issues["services"] = analysis_results["exported_services"]
    if analysis_results["exported_receivers"]:
        exported_issues["receivers"] = analysis_results["exported_receivers"]
    if analysis_results["exported_providers"]:
        exported_issues["providers"] = analysis_results["exported_providers"]
    
    return exported_issues

def check_insecure_storage(apk_file):
    insecure_storage_locations = [
        "/sdcard/",
        "/storage/emulated/",
        "/mnt/",
        "/data/data/"
    ]
    insecure_storage_issues = []
    
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        apk_contents = zip_ref.namelist()
        for file in apk_contents:
            for location in insecure_storage_locations:
                if location in file:
                    insecure_storage_issues.append(file)
    
    return insecure_storage_issues

def check_insecure_communication(strings):
    insecure_communication_patterns = [
        "http://",
    ]
    insecure_communication_uses = [s for s in strings if any(pattern in s for pattern in insecure_communication_patterns)]
    return insecure_communication_uses

def check_insecure_authentication(strings):
    auth_patterns = [
        "auth_token",
        "session_token",
    ]
    insecure_authentication_uses = [s for s in strings if any(pattern in s for pattern in auth_patterns)]
    return insecure_authentication_uses

def check_code_quality(strings):
    debug_patterns = [
        "Log.d",
        "Log.v",
        "Log.i",
    ]
    code_quality_issues = [s for s in strings if any(pattern in s for pattern in debug_patterns)]
    return code_quality_issues

def check_code_tampering(apk_file):
    tampering_files = [
        "libtamper.so",
        "tamper_protection",
    ]
    tampering_issues = []
    
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        apk_contents = zip_ref.namelist()
        for file in apk_contents:
            if any(tampering_file in file for tampering_file in tampering_files):
                tampering_issues.append(file)
    
    return tampering_issues

def check_reverse_engineering(apk_file):
    reverse_engineering_files = [
        "proguard.cfg",
        "mapping.txt",
    ]
    reverse_engineering_issues = []
    
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        apk_contents = zip_ref.namelist()
        for file in apk_contents:
            if any(reverse_file in file for reverse_file in reverse_engineering_files):
                reverse_engineering_issues.append(file)
    
    return reverse_engineering_issues

def check_extraneous_functionality(strings):
    extraneous_patterns = [
        "testFunction",
        "debugFunction",
    ]
    extraneous_uses = [s for s in strings if any(pattern in s for pattern in extraneous_patterns)]
    return extraneous_uses

def print_banner():
    banner = r"""
     ___      _    __  __ ___                 _           
    / _ \    | |  |  \/  |   \ ___ _ __  _ __(_)_ _  __ _ 
   | (_) |_  | |  | |\/| | |) / -_) '  \| '_ \ | ' \/ _` |
    \___/(_)_|_|  |_|  |_|___/\___|_|_|_| .__/_|_||_\__, |
                                        |_|         |___/ 
    """
    print(colored(banner, 'green'))

def save_results_to_file(file_path, results):
    with open(file_path, 'w', encoding='utf-8') as f:
        for category, issues in results.items():
            f.write(f"{category}\n")
            f.write("="*len(category) + "\n\n")
            if issues:
                for issue in issues:
                    try:
                        f.write(f"{issue}\n")
                    except UnicodeEncodeError:
                        continue
                f.write("\n")
            else:
                f.write("No issues detected.\n\n")

def main():
    parser = argparse.ArgumentParser(description="Extract strings and analyze APK file for OWASP vulnerabilities.")
    parser.add_argument("apk_file", help="Path to the APK file")
    parser.add_argument("output_file", help="Path to the output text file")
    args = parser.parse_args()

    print_banner()

    strings = extract_strings_from_files(args.apk_file)
    analysis_results, dex_files = analyze_apk(args.apk_file)

    results = {
        "Package Name": [analysis_results["package_name"]],
        "Permissions": analysis_results["permissions"],
        "Activities": analysis_results["activities"],
        "Services": analysis_results["services"],
        "Receivers": analysis_results["receivers"],
        "Providers": analysis_results["providers"],
        "Exported Activities": analysis_results["exported_activities"],
        "Exported Services": analysis_results["exported_services"],
        "Exported Receivers": analysis_results["exported_receivers"],
        "Exported Providers": analysis_results["exported_providers"],
        "Hardcoded Secrets": check_hardcoded_secrets(strings),
        "Insecure Permissions": check_insecure_permissions(analysis_results["permissions"]),
        "Weak Cryptography": check_weak_cryptography(dex_files),
        "Insecure Storage": check_insecure_storage(args.apk_file),
        "Insecure Communication": check_insecure_communication(strings),
        "Insecure Authentication": check_insecure_authentication(strings),
        "Code Quality Issues": check_code_quality(strings),
        "Code Tampering Issues": check_code_tampering(args.apk_file),
        "Reverse Engineering Issues": check_reverse_engineering(args.apk_file),
        "Extraneous Functionality": check_extraneous_functionality(strings)
    }

    save_results_to_file(args.output_file, results)
    print(colored(f"Results saved to {args.output_file}", 'green'))

if __name__ == "__main__":
    main()
