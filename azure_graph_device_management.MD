# Azure Graph Device Management Ansible Module

This Ansible module allows you to interact with Microsoft Graph API to manage device compliance policies, mobile applications, app configurations, and more within Azure AD groups using a Service Principal.

## Requirements

- Python 3.x
- Ansible 2.9 or higher
- `requests` library (installable via `pip install requests`)

## Prerequisites

Before using this module, ensure you have:

- Registered an Azure AD application.
- Obtained the following credentials for the application:
  - `client_id`: The Application (client) ID.
  - `client_secret`: The client secret key.
  - `tenant_id`: The Directory (tenant) ID.
- Assigned the application appropriate permissions to access Microsoft Graph API for device and application management.

## Usage

To use the `azure_graph_device_management` module, follow these steps:

1. **Save the Module:**
   Save the module code as `azure_graph_device_management.py` in your Ansible library path or include it in the same directory as your playbook.

2. **Set the Playbook:**
   Create an Ansible playbook that utilizes this module. Here's an example:

   ```yaml
   - hosts: localhost
     tasks:
       - name: Get device management info for Azure AD group using SPN
         azure_graph_device_management:
           client_id: "YOUR_CLIENT_ID"
           client_secret: "YOUR_CLIENT_SECRET"
           tenant_id: "YOUR_TENANT_ID"
           group_name: "All-Windows"       # Replace with your target group name
           device_filter: "device_filter_condition"  # Optional: Use to filter results
         register: result

       - debug:
           var: result


results:
  device_compliance_policies:
    - ... # List of device compliance policies
  applications:
    - ... # List of mobile applications
  app_configurations:
    - ... # List of app configurations
  app_protections:
    ios: 
      - ... # List of iOS managed app protections
    android:
      - ... # List of Android managed app protections
    windows:
      - ... # List of Windows managed app protections
    mdm:
      - ... # List of MDM Windows Information Protection policies
  device_configurations:
    configuration_policies:
      - ... # List of configuration policies
    device_configurations:
      - ... # List of device configurations
    group_policy_configurations:
      - ... # List of group policy configurations
    mobile_app_configurations:
      - ... # List of mobile app configurations
  remediation_scripts:
    - ... # List of remediation scripts
  platform_scripts:
    - ... # List of platform management scripts
  windows_autopilot_profiles:
    - ... # List of Windows Autopilot profiles
