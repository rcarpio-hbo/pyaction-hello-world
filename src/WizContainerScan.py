import random
from datetime import date
from pathlib import Path
import subprocess
import os

from src import io
from src.VulnerabilitiesReport import VulnerabilitiesReport

class WizContainerScan:
  
    def __init__(self, json_args):
      if not json_args:
        raise KeyError(f'Required OS variables "INPUT_WIZ_CLIENT_ID", "INPUT_WIZ_CLIENT_SECRET" and "INPUT_CONTAINER_IMAGE" must set')

      # wiz_client_id and wiz_client_secret
      try:
          self.wiz_client_id = json_args['wiz_client_id']
      except:
          raise KeyError('Required OS variable INPUT_WIZ_CLIENT_ID not set')

      try:
          self.wiz_client_secret = json_args['wiz_client_secret']
      except:
          raise KeyError('Required OS variable INPUT_WIZ_CLIENT_SECRET not set')

      self.command = "wizcli docker scan "

      # --image Flag
      if 'container_image' in json_args and json_args['container_image'] != '':
        value = json_args['container_image']
        self.command += f"--image {value} "
      else:
        raise ValueError(f'required flag "image" not set')

      # --secrets Flag
      if 'scan_secrets' in json_args and json_args['scan_secrets'] != '':
        value = json_args['scan_secrets']
        available_options = ['true', 'false']
        if not value in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{value}" for "--secret" flag. This flag does not support arguments')
        if value == 'true':
          self.command += f"--secrets "

      # --format Flag
      if 'scan_format' in json_args and json_args['scan_format'] != '':
        value = json_args['scan_format']
        available_options = ['human', 'json', 'sarif']
        if not value in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{value}" for "-f, --format" flag: must be {available_options_str}')

        self.command += f"--format {value} "

      # --group-by Flag
      group_by = ''
      if 'scan_group_by' in json_args and json_args['scan_group_by'] != '':
        group_by = json_args['scan_group_by']
        available_options = ['default', 'layer', 'resource']
        if not group_by in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{group_by}" for "--group-by" flag: must be {available_options_str}')

        self.command += f"--group-by {group_by} "

      # --policy-hits-only Flag
      policy_hits_only = ''

      if 'scan_policy_hits_only' in json_args and json_args['scan_policy_hits_only'] != '':
        policy_hits_only = json_args['scan_policy_hits_only']
        available_options = ['true', 'false']
        if not policy_hits_only in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{policy_hits_only}" for "--policy-hits-only" flag. This flag does not support arguments')
        if policy_hits_only == 'true':
          self.command += f"--policy-hits-only "

      # --show-secret-snippets Flag
      if 'scan_show_secret_snippets' in json_args and json_args['scan_show_secret_snippets'] != '':
        value = json_args['scan_show_secret_snippets']
        available_options = ['true', 'false']
        if not value in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{value}" for "--show-secret-snippets" flag. This flag does not support arguments')
        if value == 'true':
          self.command += f"--show-secret-snippets "

      # --show-vulnerability-details Flag
      if 'scan_show_vulnerability_details' in json_args and json_args['scan_show_vulnerability_details'] != '':
        value = json_args['scan_show_vulnerability_details']
        available_options = ['true', 'false']
        if not value in available_options:
          available_options_str = ", ".join(available_options)
          raise ValueError(f'Invalid argument "{value}" for "--show-vulnerability-details" flag. This flag does not support arguments')
        if value == 'true':
          self.command += f"--show-vulnerability-details "

      # --project Flag
      if 'scan_project' in json_args and json_args['scan_project'] != '':
        value = json_args['scan_project']
        self.command += f"--project {value} "

      # --tag Flag
      if 'scan_tag' in json_args and json_args['scan_tag'] != '':
        value = json_args['scan_tag']
        self.command += f"--tag {value} "

      # --policy Flag
      if 'scan_policy' in json_args and json_args['scan_policy'] != '':
        value = json_args['scan_policy']
        self.command += f"--policy '{value}' "

      # --output Flag
      self.report_path = ''
      self.wiz_output_file_path = ''

      if 'report_name' in json_args and json_args['report_name'] != '':
        report_name = json_args['report_name']    
        random_number = random.randint(100000, 999999)
        date_today = date.today().strftime("%Y_%m_%d")  
        self.report_path = f'output/{random_number}__{date_today}__{report_name}'

        wiz_output_file_path = self.report_path
        # Set file format
        if '.' not in report_name:
          report_file_format = 'human'
        else:
          file_extension = report_name.split('.')[-1]
          if file_extension == 'zip':
            report_file_format = 'csv-zip'
          # wiz does not support html neither excel. 
          # a custom script is developed to convert a json to html/excel
          elif file_extension == 'json' or file_extension == 'html' or file_extension == 'xlsx':
            report_file_format = 'json'
            wiz_output_file_path = ".".join(self.report_path.split('.')[0:-1]) + '.json'
          elif file_extension == 'sarif':
            report_file_format = 'sarif'
          elif file_extension == 'txt':
            report_file_format = 'human'
          else:
            raise ValueError(f'The file format is not supported "{report_name}" : must be:\n    csv-zip: report-example.zip\n    human: report-example.txt or report-example\n    json: report-example.json\n    sarif: report-example.sarif\n    html: report-example.html\n    xlsx: report-example.xlsx')

        self.wiz_output_file_path = wiz_output_file_path

        # Set output Flag
        report_command = f'{wiz_output_file_path},{report_file_format}'
        if (policy_hits_only !='' and group_by !='') or group_by !='':
          report_command += f',{policy_hits_only},{group_by}'
        elif policy_hits_only !='':
          report_command += f',{policy_hits_only}'

        self.command += f"--output {report_command} "


      # --timeout Flag
      if 'scan_timeout' in json_args and json_args['scan_timeout'] !='':
        value = json_args['scan_timeout']
        self.command += f"--timeout '{value}' "

      # --dockerfile Flag
      if 'scan_used_dockerfile' in json_args and json_args['scan_used_dockerfile'] !='':
        value = json_args['scan_used_dockerfile']
        self.command += f"--dockerfile '{value}' "

      # action_exit_code
      if 'action_exit_code' in json_args and json_args['action_exit_code'] !='':
        self.action_exit_code = json_args['action_exit_code']
      else:
        self.action_exit_code = None

 
    def run_scan(self):
      """executes wiz docker scan command"""

      if self.report_path != '':
        print('\n📁 Make output directory if does not exist')
        Path('output').mkdir(parents=True, exist_ok=True)

      print(f'\n🏃 Executing: {self.command}', flush=True)
      completed_scan = subprocess.run(self.command,
                              text=True,
                              shell=True,
                              universal_newlines=True)

      scan_exit_code = completed_scan.returncode

      if scan_exit_code == 0:
          io.write_to_summary("🎉 Kudos, container image meets policy requirements!&nbsp; &nbsp; ![Passed](https://img.shields.io/badge/-Passed-brightgreen)\n")
          return "PASSED_BY_POLICY"
      elif scan_exit_code == 1:
          exit(1)
      elif scan_exit_code == 2:
          exit(2)
      elif scan_exit_code == 3:
          exit(3)
      elif scan_exit_code == 4:
          io.write_to_summary("❌ Container image does not meet policy requirements!&nbsp; &nbsp; ![Failed](https://img.shields.io/badge/-Failed-red)\n")
          return 'FAILED_BY_POLICY'
      else:
          print('Unknown exit code')
          exit(1)

    def generate_report(self):
      """generates a custom vulnerability report"""
      vuln_report = VulnerabilitiesReport(self.wiz_output_file_path, self.report_path)

      if self.wiz_output_file_path == '': 
        print("Report not generated")
        return vuln_report

      if self.wiz_output_file_path.endswith('.json'):
          if self.report_path.endswith('.html'):
              vuln_report.create_html_report()

          if self.report_path.endswith('.xlsx'):
              vuln_report.create_excel_report()

      return vuln_report

    def run_authentication(self):
      """executes wiz auth command"""
      print('🔑 Authenticate to Wiz', flush=True)
      cmd = f'wizcli auth --id {self.wiz_client_id}  --secret {self.wiz_client_secret}'
      completed_auth = subprocess.run(cmd,
                              text=True,
                              shell=True,
                              universal_newlines=True)

      scan_exit_code = completed_auth.returncode

      if scan_exit_code != 0:
        exit(1)
      else:
        return scan_exit_code