import json

from src import io
from src.WizContainerScan import WizContainerScan

        
def main() -> None:

    inputs = io.serialize_inputs()
    print("🛠️ Github Action Configuration")
    print(json.dumps(inputs, indent=2))

    wiz_scan = WizContainerScan(inputs)

    wiz_scan.run_authentication()
    wiz_scan_status = wiz_scan.run_scan()

    vuln_report = wiz_scan.generate_report()
    vuln_report.write_github_summary()


    # only writes if we are in github
    io.write_to_output(
            {
                'report_path' : vuln_report.report_path,
                'wiz_scan_status' :  wiz_scan_status
            }
    )

    if wiz_scan_status == "PASSED_BY_POLICY":
        exit(0)
    else:
        if not wiz_scan.action_exit_code == None:
            exit (int(wiz_scan.action_exit_code))
        exit(1)


if __name__ == "__main__":
    main()

