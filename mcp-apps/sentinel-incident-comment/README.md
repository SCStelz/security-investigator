# Add Comment to Sentinel Incident

This solution enables adding comments to Microsoft Sentinel incidents via an MCP tool. It consists of two components:
1. **Azure Logic App** - Handles the Sentinel API interaction with secure authentication
2. **MCP Server** - Exposes the functionality as an MCP tool for VS Code Copilot

## When to Use This Solution

This solution was specifically designed for environments where:
- The Azure Logic App must use the **Consumption** hosting model
- **Azure API Management (APIM)** cannot be deployed
- No other hosted MCP Server gateway is available

### Alternative Approaches

If these constraints don't apply to your environment, consider these simpler alternatives:

| Alternative | Description |
|-------------|-------------|
| **Azure Logic Apps (Standard)** | Standard Logic Apps with an HTTP trigger can be directly exposed as MCP Servers without requiring a separate local MCP Server component |
| **Azure API Management** | APIM can expose any API (including Logic App endpoints) as an MCP Server, providing centralized management and additional capabilities |

If you can use either of these alternatives, they eliminate the need for the local Node.js MCP Server component in this solution.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   VS Code   │────▶│ MCP Server  │────▶│  Logic App  │────▶│  Sentinel   │
│   Copilot   │     │  (local)    │     │  (Azure)    │     │    API      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                          │
                    Uses webhook URL
                    from env variable
```

---

# Part 1: Logic App

The Logic App `Sentinel-Incident-Add-Comment` provides a secure HTTPS endpoint that receives a Defender incident ID and message, looks up the corresponding Sentinel incident via Log Analytics query, then calls the Sentinel REST API directly via HTTP to add the comment.

## Logic App Deployment

### Step 1: Deploy the ARM Template

**Azure CLI:**
```bash
# Set variables
RESOURCE_GROUP="Sentinel-Incident-Add-Comment-rg"
SENTINEL_RG="your-sentinel-resource-group"
SENTINEL_WORKSPACE="your-sentinel-workspace"
LOCATION="eastus"

# Create resource group (if needed)
az group create --name $RESOURCE_GROUP --location $LOCATION

# Deploy the Logic App
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file infra/Sentinel-Incident-Add-Comment.json \
  --parameters resourceGroupName=$SENTINEL_RG workspaceName=$SENTINEL_WORKSPACE
```

**PowerShell:**
```powershell
$ResourceGroup = "Sentinel-Incident-Add-Comment-rg"
$SentinelRG = "your-sentinel-resource-group"
$SentinelWorkspace = "your-sentinel-workspace"
$Location = "eastus"

# Create resource group (if needed)
New-AzResourceGroup -Name $ResourceGroup -Location $Location

# Deploy the Logic App
New-AzResourceGroupDeployment `
  -ResourceGroupName $ResourceGroup `
  -TemplateFile "infra\Sentinel-Incident-Add-Comment.json" `
  -resourceGroupName $SentinelRG `
  -workspaceName $SentinelWorkspace
```

### Step 2: Assign Permissions

The Logic App's Managed Identity needs **Microsoft Sentinel Responder** role:

```bash
# Get the Logic App's Principal ID
PRINCIPAL_ID=$(az logic workflow show -g $RESOURCE_GROUP -n "Sentinel-Incident-Add-Comment" --query identity.principalId -o tsv)

# Assign Sentinel Responder role
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/<subscription-id>/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$SENTINEL_WORKSPACE"
```

### Step 3: Get the Webhook URL

After deployment and configuration, retrieve the webhook URL:

**Azure Portal:**
1. Open the Logic App
2. Click on the **"When a HTTP request is received"** trigger
3. Copy the **HTTP POST URL**

**Azure CLI:**
```bash
az rest --method post \
  --uri "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Logic/workflows/Sentinel-Incident-Add-Comment/triggers/When_a_HTTP_request_is_received/listCallbackUrl?api-version=2016-06-01" \
  --query value -o tsv
```

---

# Part 2: MCP Server

The MCP Server exposes the `add_comment_to_sentinel_incident` tool that calls the Logic App webhook securely.

## MCP Server Deployment

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Build the Server

```bash
npm run build
```

### Step 3: Configure VS Code

Add to your VS Code `settings.json` or workspace settings:

```json
{
  "mcp.servers": {
    "sentinel-incident-comment": {
      "command": "node",
      "args": ["c:/gh/mcp-add-comment-to-sentinel-incident/dist/index.js", "--stdio"],
      "env": {
        "SENTINEL_COMMENT_WEBHOOK_URL": "<YOUR_LOGIC_APP_WEBHOOK_URL>"
      }
    }
  }
}
```

Replace `<YOUR_LOGIC_APP_WEBHOOK_URL>` with the webhook URL obtained in Part 1, Step 3.

## MCP Tool Usage

### Tool: `add_comment_to_sentinel_incident`

Adds a comment to a Microsoft Sentinel incident.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `incidentId` | string | Yes | The Sentinel incident ID (e.g., "12345") |
| `message` | string | Yes | Comment text (plain text or HTML) |

### Calling from GitHub Copilot (Natural Language)

Once the MCP Server is configured, you can invoke it from GitHub Copilot Chat using natural language. Here are some examples:

**Simple comment:**
> "Add a comment to Sentinel incident 12345 saying that the investigation is complete and no malicious activity was found"

**Detailed investigation summary:**
> "Add a comment to incident 2847 with the following findings: the user confirmed this was legitimate activity, the source IP belongs to our corporate VPN, and no indicators of compromise were detected. Recommend closing as false positive."

**HTML formatted comment:**
> "Add an HTML-formatted comment to incident 5123 with a heading 'AI Analysis Results', a bullet list of findings, and a bold recommendation section"

GitHub Copilot will automatically invoke the `add_comment_to_sentinel_incident` tool with the appropriate parameters.

### Programmatic Usage (Without MCP Server)

For programmatic access to the Logic App directly (e.g., from scripts, automation pipelines, or other applications), see the [Logic App README](infra/README.md) which includes examples using curl, PowerShell, and Python.

### Response

**Success:**
```json
{
  "status": "success",
  "message": "Comment added to incident 12345",
  "incidentId": "12345"
}
```

**Error:**
```json
{
  "status": "error",
  "message": "Failed to add comment to incident",
  "incidentId": "12345",
  "error": { ... }
}
```

---

## Security Considerations

1. **Webhook URL Protection**: The Logic App webhook URL contains a SAS signature. Treat it as a secret.
2. **Environment Variables**: Never commit webhook URLs to source control.
3. **Access Control**: The Logic App's Managed Identity controls access to Sentinel. Ensure proper RBAC.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "SENTINEL_COMMENT_WEBHOOK_URL not set" | Set the environment variable in VS Code MCP settings |
| 401 Unauthorized | Verify the Logic App's Managed Identity is properly configured |
| 403 Forbidden | Verify the Logic App's Managed Identity has "Microsoft Sentinel Responder" role |
| 404 Not Found | Check the incident ID exists in your Sentinel workspace |
| Connection timeout | Verify network connectivity to Azure Logic Apps |

## Related Resources

- [Logic App ARM Template](infra/Sentinel-Incident-Add-Comment.json)
- [Microsoft Sentinel Incidents API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
