# report_generator.py

def generate_compliance_report(results):
    """Generate a compliance report based on the results of the tests"""
    report = "API Security Compliance Report\n"
    report += "=" * 40 + "\n"
    
    for test, result in results.items():
        status, message = result
        report += f"{test}:\n"
        report += f"  Status: {'PASS' if status else 'FAIL'}\n"
        report += f"  Details: {message}\n"
        report += "-" * 40 + "\n"

    return report
