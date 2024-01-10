from jinja2 import Template, Environment, FileSystemLoader
import pandas as pd
from datetime import datetime
import os

from src import io
from src import utils

class VulnerabilitiesReport:

    def __init__(self, wiz_output_file_path, report_path):
        self.wiz_output_file_path = wiz_output_file_path
        self.report_path = report_path
        self.json_report = {}
        if  wiz_output_file_path.endswith('.json'):
            self.json_report = utils.read_json(self.wiz_output_file_path)

    def get_scanning_status(self):
        """return scan result"""
        return self.json_report['status']['verdict']

    def write_github_summary(self):
        """writes a markdown summary on the Actions run summary page"""
        io.write_to_summary('### Vulnerabilities:')
        if bool(self.json_report):
            summary = self.get_vulnerabilities_summary()
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🔴 **CRITICAL:** {summary['critical_vuln']}")
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🟠 **HIGH:** {summary['high_vuln']}")
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🟡 **MEDIUM:** {summary['medium_vuln']}")
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🟢 **LOW:** {summary['low_vuln']}")
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🔵 **INFO:** {summary['info_vuln']}")
            io.write_to_summary(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;⚪ **UNFIXED:** {summary['unfixed_vuln']}")
            io.write_to_summary(f"")
            io.write_to_summary(f"Total: {summary['total_vuln']}, out of which {summary['fixable_vuln']} are fixable")
        else:
            io.write_to_summary('See logs above for details.')
        
        return

    def get_vulnerabilities_summary(self):
        """returns a dictionary containing a summary"""
        vuln_summary = {
            'critical_vuln' : self.json_report['result']['analytics']['vulnerabilities']['criticalCount'],
            'high_vuln' : self.json_report['result']['analytics']['vulnerabilities']['highCount'],
            'medium_vuln' : self.json_report['result']['analytics']['vulnerabilities']['mediumCount'],
            'low_vuln' : self.json_report['result']['analytics']['vulnerabilities']['lowCount'],
            'info_vuln' : self.json_report['result']['analytics']['vulnerabilities']['infoCount'],
            'unfixed_vuln' : self.json_report['result']['analytics']['vulnerabilities']['unfixedCount']
        }

        vuln_summary["total_vuln"] = vuln_summary['critical_vuln'] + vuln_summary['high_vuln'] + vuln_summary['medium_vuln']+ vuln_summary['low_vuln'] + vuln_summary['info_vuln']
        vuln_summary["fixable_vuln"] = vuln_summary['total_vuln'] - vuln_summary['unfixed_vuln']

        return vuln_summary

    def get_vulnerabilities (self):
        """extracts vulnerabilities from wiz report"""
        # Wiz vulnerabilities types
        vuln_types = ["applications","cpes","libraries","osPackages"]

        vulnerabilities = []
        for v_type in vuln_types:
          result_by_type = self.json_report['result'][v_type]
          if result_by_type is None:
            print("✅ This image does not have " + v_type + " vulnerabilities")
            continue    
          for r in result_by_type:
              # Path value
              if "path" in r:
                  path = r['path']
              else: 
                  path = '-'

              for vuln in r['vulnerabilities']:
                  # Fixed Version value
                  if vuln['fixedVersion'] == None:
                      fixedVersion = '-'
                  else: 
                      fixedVersion = vuln['fixedVersion'] 

                  data_vuln = {
                      'Type': v_type,
                      'Name': r['name'], 
                      'Path': path, 
                      'Version': r['version'],
                      'Fixed Version': fixedVersion,
                      'CVE': vuln['name'],
                      'Severity': vuln['severity'],
                      'Source': '<a href="' + vuln['source'] + '">More information</a>'
                  }
                  vulnerabilities.append(data_vuln)

        return vulnerabilities

    def get_secrets (self):
        """extracts secrets from wiz report"""
        result_secrets = self.json_report['result']['secrets']
        if result_secrets is None:
            print("✅ This image does not contain secrets")
            return None

        secrets = []

        for secret in result_secrets:
            s = {
                'Secret Instance' : secret['description'],
                'Path' : secret['path'],
                'Line Number' : secret['lineNumber'],
                'Offset' : secret['offset'],
                'Type' : secret['type'],
            }
            secrets.append(s)

        return secrets

    def create_html_report (self):
        """Generates vulnerabilities html report"""
        vulnerabilities = self.get_vulnerabilities()
        secrets = self.get_secrets()

        if vulnerabilities == [] and secrets == None:
          print("\n🎉 Congratulations!!! The container image does not have vulnerabilities and does not contain secrets")
          return

        pd.set_option('colheader_justify', 'center') 
        vuln_html_table = None
        secrets_html_table = None

        print('\n📋 Creating HTML report')
        # Vulnerabilities Table
        if not vulnerabilities == []:
          df_vuln = pd.DataFrame(vulnerabilities) 
          vuln_html_table = df_vuln.to_html(index=False, border=0, classes='table table-bordered table-striped', escape=False) 
          vuln_html_table = vuln_html_table.replace('<tbody>', '<tbody id="myTable">')

        # Secrets Table
        if not secrets == None:
          df_secrets = pd.DataFrame(secrets)
          secrets_html_table = df_secrets.to_html(index=False, border=0, classes='table table-bordered table-striped', escape=False) 

        # Report Status
        scanning_status = self.get_scanning_status()

        # Vulnerabilities Result Summary
        vuln_summary = self.get_vulnerabilities_summary()

        # Metadata
        scan_metadata = {
          'scan_time' : datetime.fromisoformat(self.json_report['createdAt']).strftime('%B %d, %Y at %I:%M%p'),
          'image_scanned' : self.json_report['scanOriginResource']['name'],
          'files_scanned' : self.json_report['result']['analytics']['filesScannedCount'],
          'directories_scanned' : self.json_report['result']['analytics']['directoriesScannedCount'],
          'committed_by' : os.getenv('GITHUB_ACTOR'),
          'commit_hash' : os.getenv('GITHUB_SHA'),
          'branch_name' : os.getenv('GITHUB_REF_NAME'),
          'github_repository' : os.getenv('GITHUB_REPOSITORY'),
          'github_server_url' : os.getenv('GITHUB_SERVER_URL'),
          'evaluated_policies' : ', '.join([policy['name'] for policy in self.json_report['policies']])
        }

        # Render Template
        # load templates folder to environment (security measure)
        env = Environment(loader=FileSystemLoader('template'))

        # load the `index.jinja` template and render
        report_template = env.get_template('report_template.jinja')
        output_from_parsed_template = report_template.render(vulnerabilities_table=vuln_html_table,
                                                          secrets_table=secrets_html_table,
                                                          scanning_status=scanning_status,
                                                          vuln_summary=vuln_summary,
                                                          scan_metadata=scan_metadata
                                                          )

        # write the parsed template
        with open(self.report_path, "w") as f:
          f.write(output_from_parsed_template)

        print(f'📋 HTML report created: {self.report_path}\n')
        os.remove(self.wiz_output_file_path)

        return

    def create_excel_report (self):
        vulnerabilities = self.get_vulnerabilities()
        secrets = self.get_secrets()

        if vulnerabilities == [] and secrets == None:
            print("\n🎉 Congratulations!!! The container image does not have vulnerabilities and does not contain secrets")
            return

        print('\n📋 Creating Excel report')
        with pd.ExcelWriter(self.report_path) as writer:
            # Vulnerabilities Table
            if not vulnerabilities == []:
                df_vuln = pd.DataFrame(vulnerabilities)
                df_vuln.to_excel(writer, sheet_name='Vulnerabilities', index=False)

            # Secrets Table
            if not secrets == None:
                df_secrets = pd.DataFrame(secrets)
                df_secrets.to_excel(writer, sheet_name='Secrets', index=False)

        print(f'📋 Excel report created: {self.report_path}\n')
        os.remove(self.wiz_output_file_path)
        
        return