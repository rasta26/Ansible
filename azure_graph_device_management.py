#!/usr/bin/env python

from ansible.module_utils.basic import AnsibleModule
import requests

def get_access_token(client_id, client_secret, tenant_id):
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    response = requests.post(token_url, headers=headers, data=body)
    response.raise_for_status()
    return response.json()['access_token']

def connect_graph(api_url, headers):
    response = requests.get(api_url, headers=headers)
    response.raise_for_status()
    return response.json()

def retrieve_info(group_id, headers, device_filter=None):
    results = {
        'device_compliance_policies': [],
        'applications': [],
        'app_configurations': [],
        'app_protections': {},
        'device_configurations': {},
        'remediation_scripts': [],
        'platform_scripts': [],
        'windows_autopilot_profiles': [],
    }

    # Define resources
    resources = {
        "device_compliance": "deviceManagement/deviceCompliancePolicies",
        "applications": "deviceAppManagement/mobileApps",
        "app_configurations": "deviceAppManagement/targetedManagedAppConfigurations",
        "app_protections": {
            "ios": "deviceAppManagement/iosManagedAppProtections",
            "android": "deviceAppManagement/androidManagedAppProtections",
            "windows": "deviceAppManagement/windowsManagedAppProtections",
            "mdm": "deviceAppManagement/mdmWindowsInformationProtectionPolicies",
        },
        "device_configurations": {
            "configuration_policies": "deviceManagement/configurationPolicies",
            "device_configurations": "deviceManagement/deviceConfigurations",
            "group_policy_configurations": "deviceManagement/groupPolicyConfigurations",
            "mobile_app_configurations": "deviceAppManagement/mobileAppConfigurations",
        },
        "remediation_scripts": "deviceManagement/deviceHealthScripts",
        "platform_scripts": "deviceManagement/deviceManagementScripts",
        "autopilot_profiles": "deviceManagement/windowsAutopilotDeploymentProfiles",
    }

    # Helper function to apply device filtering if specified
    def is_matching_assignment(item, group_id):
        return item.get('assignments', {}).get('target', {}).get('groupId') == group_id

    # Retrieve Device Compliance Policies
    uri = f"{api_url}/{resources['device_compliance']}?$expand=Assignments"
    for item in connect_graph(uri, headers).get('value', []):
        if is_matching_assignment(item, group_id):
            results['device_compliance_policies'].append(item)

    # Applications
    uri = f"{api_url}/{resources['applications']}?$expand=Assignments"
    for item in connect_graph(uri, headers).get('value', []):
        if is_matching_assignment(item, group_id):
            results['applications'].append(item)

    # App Configurations
    uri = f"{api_url}/{resources['app_configurations']}?$expand=Assignments"
    for item in connect_graph(uri, headers).get('value', []):
        if is_matching_assignment(item, group_id):
            results['app_configurations'].append(item)

    # App Protections
    for key, resource in resources['app_protections'].items():
        uri = f"{api_url}/{resource}?$expand=Assignments"
        for item in connect_graph(uri, headers).get('value', []):
            if is_matching_assignment(item, group_id):
                if key not in results['app_protections']:
                    results['app_protections'][key] = []
                results['app_protections'][key].append(item)

    # Device Configurations
    for key, resource in resources['device_configurations'].items():
        uri = f"{api_url}/{resource}?$expand=Assignments"
        for item in connect_graph(uri, headers).get('value', []):
            if is_matching_assignment(item, group_id):
                if key not in results['device_configurations']:
                    results['device_configurations'][key] = []
                results['device_configurations'][key].append(item)

    # Remediation Scripts
    uri = f"{api_url}/{resources['remediation_scripts']}"
    remediation_scripts = connect_graph(uri, headers).get('value', [])
    for script in remediation_scripts:
        script_assignments_uri = f"{uri}/{script['id']}/assignments"
        assignments = connect_graph(script_assignments_uri, headers).get('value', [])
        if any(is_matching_assignment(a, group_id) for a in assignments):
            results['remediation_scripts'].append(script)

    # Platform Scripts
    uri = f"{api_url}/{resources['platform_scripts']}"
    platform_scripts = connect_graph(uri, headers).get('value', [])
    for script in platform_scripts:
        script_assignments_uri = f"{uri}/{script['id']}/assignments"
        assignments = connect_graph(script_assignments_uri, headers).get('value', [])
        if any(is_matching_assignment(a, group_id) for a in assignments):
            results['platform_scripts'].append(script)

    # Windows Autopilot Profiles
    uri = f"{api_url}/{resources['autopilot_profiles']}?$expand=Assignments"
    autopilot_profiles = connect_graph(uri, headers).get('value', [])
    for profile in autopilot_profiles:
        profile_assignments_uri = f"{uri}/{profile['id']}/assignments"
        assignments = connect_graph(profile_assignments_uri, headers).get('value', [])
        if any(is_matching_assignment(a, group_id) for a in assignments):
            results['windows_autopilot_profiles'].append(profile)

    return results

def main():
    module_args = dict(
        client_id=dict(type='str', required=True),
        client_secret=dict(type='str', required=True, no_log=True),
        tenant_id=dict(type='str', required=True),
        group_name=dict(type='str', required=True),
        device_filter=dict(type='str', required=False)  # New argument for device filtering
    )
    
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    client_id = module.params['client_id']
    client_secret = module.params['client_secret']
    tenant_id = module.params['tenant_id']
    group_name = module.params['group_name']
    device_filter = module.params.get('device_filter')

    # Get access token
    try:
        token = get_access_token(client_id, client_secret, tenant_id)
    except Exception as e:
        module.fail_json(msg=f"Failed to obtain access token: {str(e)}")

    api_url = "https://graph.microsoft.com/beta"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }

    # Get Group ID
    group_uri = f"https://graph.microsoft.com/beta/groups?$filter=displayName eq '{group_name}'"
    group_response = connect_graph(group_uri, headers)
    
    if not group_response['value']:
        module.fail_json(msg=f'Group {group_name} not found.')
    
    group_id = group_response['value'][0]['id']

    # Retrieve Information
    results = retrieve_info(group_id, headers, device_filter)

    module.exit_json(changed=False, results=results)

if __name__ == '__main__':
    main()
