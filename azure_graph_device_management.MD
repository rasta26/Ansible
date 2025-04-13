**Usage:
- hosts: localhost
  tasks:
    - name: Get device management info for Azure AD group using SPN
      azure_graph_device_management:
        client_id: "YOUR_CLIENT_ID"
        client_secret: "YOUR_CLIENT_SECRET"
        tenant_id: "YOUR_TENANT_ID"
        group_name: "All-Windows"
        device_filter: "device_filter_condition"  # Optional: Use as needed for filtering
      register: result

    - debug:
        var: result
