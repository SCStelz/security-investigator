# Sentinel-Incident-Add-Comment Logic App

Azure Consumption Logic App that adds comments to Microsoft Sentinel/Defender incidents via a secure HTTPS webhook.

## Features

- **Secure HTTPS Trigger**: SAS-authenticated webhook endpoint
- **Managed Identity**: Uses System-Assigned Managed Identity for Sentinel API authentication
- **Direct HTTP API Calls**: Uses direct HTTP calls to the Sentinel REST API (no connector dependencies)
- **Incident Lookup**: Automatically looks up Sentinel incident ID from Defender incident ID via Log Analytics query
- **Input Validation**: Schema-enforced JSON payload with required fields
- **HTML Support**: Message field accepts both plain text and HTML formatting
- **Error Handling**: Returns appropriate HTTP status codes (200/404/500) with response details

## Deployment

### Prerequisites

1. Azure subscription with Microsoft Sentinel workspace
2. Permissions to create Logic Apps
3. Azure CLI or PowerShell with Az module

### Deploy via Azure CLI

```bash
# Set variables
RESOURCE_GROUP="your-resource-group"
SENTINEL_RG="sentinel-resource-group"
SENTINEL_WORKSPACE="your-sentinel-workspace"
LOCATION="eastus"

# Deploy the Logic App
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file Sentinel-Incident-Add-Comment.json \
  --parameters resourceGroupName=$SENTINEL_RG workspaceName=$SENTINEL_WORKSPACE
```

### Deploy via PowerShell

```powershell
# Set variables
$ResourceGroup = "your-resource-group"
$SentinelRG = "sentinel-resource-group"
$SentinelWorkspace = "your-sentinel-workspace"

# Deploy the Logic App
New-AzResourceGroupDeployment `
  -ResourceGroupName $ResourceGroup `
  -TemplateFile "Sentinel-Incident-Add-Comment.json" `
  -resourceGroupName $SentinelRG `
  -workspaceName $SentinelWorkspace
```

## Post-Deployment: Assign Permissions

The Logic App's Managed Identity needs **Microsoft Sentinel Responder** role on the Sentinel workspace:

```bash
# Get the Logic App's Principal ID (from deployment output)
PRINCIPAL_ID=$(az logic workflow show -g $RESOURCE_GROUP -n "Sentinel-Incident-Add-Comment" --query identity.principalId -o tsv)

# Assign Sentinel Responder role
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/<subscription-id>/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$SENTINEL_WORKSPACE"
```

## Usage

### Request Format

**Endpoint**: `POST <webhook-url>`

**Headers**:
```
Content-Type: application/json
```

**Body**:
```json
{
  "incidentId": "<incident-arm-id-or-number>",
  "message": "<comment-text-or-html>"
}
```

### Input Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `incidentId` | string | Yes | Sentinel incident ARM resource ID or incident number |
| `message` | string | Yes | Comment text (plain text or HTML) |

### Example: Plain Text Comment

```bash
curl -X POST "<webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{
    "incidentId": "12345",
    "message": "Investigation completed. No malicious activity found."
  }'
```

### Example: HTML Comment

```bash
curl -X POST "<webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{
    "incidentId": "12345",
    "message": "<h3>Investigation Summary</h3><ul><li>User verified legitimate</li><li>Activity from known VPN</li><li>No IOCs detected</li></ul><p><strong>Status:</strong> False Positive</p>"
  }'
```

### Example: PowerShell

```powershell
$webhookUrl = "<webhook-url>"
$body = @{
    incidentId = "12345"
    message = "Automated investigation completed by Copilot. See attached report for details."
} | ConvertTo-Json

Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
```

### Example: Python

```python
import requests

webhook_url = "<webhook-url>"
payload = {
    "incidentId": "12345",
    "message": "<b>AI Analysis:</b> This incident appears to be a true positive based on anomaly detection."
}

response = requests.post(webhook_url, json=payload)
print(response.json())
```

## Response Format

### Success (HTTP 200)

```json
{
  "status": "success",
  "message": "Comment added to incident 12345",
  "incidentId": "12345"
}
```

### Failure (HTTP 500)

```json
{
  "status": "error",
  "message": "Failed to add comment to incident",
  "incidentId": "12345",
  "error": { ... }
}
```

## Security Considerations

1. **Webhook URL Security**: The webhook URL contains a SAS token. Treat it as a secret and store securely.
2. **Managed Identity**: Uses System-Assigned Managed Identity for secure, keyless authentication to Sentinel REST APIs.
3. **Direct API Access**: Uses direct HTTP calls to Azure Management APIs instead of connector actions, avoiding design-time authorization issues.
4. **Input Validation**: Schema validation ensures only properly formatted requests are processed.
5. **Secure Data**: Trigger inputs/outputs are marked as secure to prevent logging sensitive data.

## Getting the Webhook URL

After deployment, retrieve the webhook URL:

### Azure CLI
```bash
az logic workflow show -g $RESOURCE_GROUP -n "Sentinel-Incident-Add-Comment" \
  --query "accessEndpoint" -o tsv
```

### Azure Portal
1. Open the Logic App in Azure Portal
2. Click on the **When a HTTP request is received** trigger
3. Copy the **HTTP POST URL**

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Managed Identity not properly configured for Azure Management API. |
| 403 Forbidden | Managed Identity missing Sentinel Responder role. |
| 404 Not Found | Invalid incident ID or workspace parameters. |
| 400 Bad Request | Malformed JSON or missing required fields. |

## Template Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `logicAppName` | Sentinel-Incident-Add-Comment | Name of the Logic App |
| `location` | Resource group location | Azure region |
| `sentinelConnectionName` | azuresentinel | API connection name |
| `subscriptionId` | Current subscription | Target subscription |
| `resourceGroupName` | *Required* | Sentinel workspace resource group |
| `workspaceName` | *Required* | Sentinel workspace name |

## Integration with Security Investigator

This Logic App can be called from the Security Investigator scripts to automatically add investigation findings as incident comments:

```python
import requests

def add_incident_comment(incident_id: str, comment: str, webhook_url: str):
    """Add a comment to a Sentinel incident via Logic App webhook."""
    response = requests.post(
        webhook_url,
        json={"incidentId": incident_id, "message": comment},
        timeout=30
    )
    response.raise_for_status()
    return response.json()
```
