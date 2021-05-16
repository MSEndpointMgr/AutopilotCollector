using namespace System.Net

# Input bindings are passed in via param block.
param([string] $QueueItem, $TriggerMetadata)

# Functions
function Get-AuthToken {
    <#
    .SYNOPSIS
        Retrieve an access token for using the client credentials flow.
        
    .DESCRIPTION
        Retrieve an access token for using the client credentials flow.
        
    .PARAMETER TenantID
        Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>.
        
    .PARAMETER ClientID
        Application ID (Client ID) for an Azure AD service principal.
        
    .PARAMETER ClientSecret
        Specify the client secret for an Azure AD service principal.
        
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-04-28
        Updated:     2021-04-28

        Version history:
        1.0.0 - (2021-04-28) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>.")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantID,

        [parameter(Mandatory = $true, HelpMessage = "Application ID (Client ID) for an Azure AD service principal.")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientID,

        [parameter(Mandatory = $true, HelpMessage = "Specify the client secret for an Azure AD service principal.")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret
    )
    Process {
        # Force TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $AuthBody = @{
            grant_type = "client_credentials"
            resource = "https://graph.microsoft.com"
            client_id = $ClientID
            client_secret = $ClientSecret
        }
        $AuthURI = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
        $Response = Invoke-RestMethod -Method "Post" -Uri $AuthURI -Body $AuthBody

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
        }

        # Handle return value
        return $AuthenticationHeader
    }
}

function Invoke-MSGraphOperation {
    <#
    .SYNOPSIS
        Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
        
    .DESCRIPTION
        Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
        This function handles nextLink objects including throttling based on retry-after value from Graph response.
        
    .PARAMETER Get
        Switch parameter used to specify the method operation as 'GET'.
        
    .PARAMETER Post
        Switch parameter used to specify the method operation as 'POST'.
        
    .PARAMETER Patch
        Switch parameter used to specify the method operation as 'PATCH'.
        
    .PARAMETER Put
        Switch parameter used to specify the method operation as 'PUT'.
        
    .PARAMETER Delete
        Switch parameter used to specify the method operation as 'DELETE'.
        
    .PARAMETER Resource
        Specify the full resource path, e.g. deviceManagement/auditEvents.
        
    .PARAMETER Headers
        Specify a hash-table as the header containing minimum the authentication token.
        
    .PARAMETER Body
        Specify the body construct.
        
    .PARAMETER APIVersion
        Specify to use either 'Beta' or 'v1.0' API version.
        
    .PARAMETER ContentType
        Specify the content type for the graph request.
        
    .NOTES
        Author:      Nickolaj Andersen & Jan Ketil Skanke
        Contact:     @JankeSkanke @NickolajA
        Created:     2020-10-11
        Updated:     2020-11-11

        Version history:
        1.0.0 - (2020-10-11) Function created
        1.0.1 - (2020-11-11) Verified
    #>    
    param(
        [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Switch parameter used to specify the method operation as 'GET'.")]
        [switch]$Get,

        [parameter(Mandatory = $true, ParameterSetName = "POST", HelpMessage = "Switch parameter used to specify the method operation as 'POST'.")]
        [switch]$Post,

        [parameter(Mandatory = $true, ParameterSetName = "PATCH", HelpMessage = "Switch parameter used to specify the method operation as 'PATCH'.")]
        [switch]$Patch,

        [parameter(Mandatory = $true, ParameterSetName = "PUT", HelpMessage = "Switch parameter used to specify the method operation as 'PUT'.")]
        [switch]$Put,

        [parameter(Mandatory = $true, ParameterSetName = "DELETE", HelpMessage = "Switch parameter used to specify the method operation as 'DELETE'.")]
        [switch]$Delete,

        [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Specify the full resource path, e.g. deviceManagement/auditEvents.")]
        [parameter(Mandatory = $true, ParameterSetName = "POST")]
        [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
        [parameter(Mandatory = $true, ParameterSetName = "PUT")]
        [parameter(Mandatory = $true, ParameterSetName = "DELETE")]
        [ValidateNotNullOrEmpty()]
        [string]$Resource,

        [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Specify a hash-table as the header containing minimum the authentication token.")]
        [parameter(Mandatory = $true, ParameterSetName = "POST")]
        [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
        [parameter(Mandatory = $true, ParameterSetName = "PUT")]
        [parameter(Mandatory = $true, ParameterSetName = "DELETE")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$Headers,

        [parameter(Mandatory = $false, ParameterSetName = "POST", HelpMessage = "Specify the body construct.")]
        [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
        [parameter(Mandatory = $true, ParameterSetName = "PUT")]
        [ValidateNotNullOrEmpty()]
        [System.Object]$Body,

        [parameter(Mandatory = $false, ParameterSetName = "GET", HelpMessage = "Specify to use either 'Beta' or 'v1.0' API version.")]
        [parameter(Mandatory = $false, ParameterSetName = "POST")]
        [parameter(Mandatory = $false, ParameterSetName = "PATCH")]
        [parameter(Mandatory = $false, ParameterSetName = "PUT")]
        [parameter(Mandatory = $false, ParameterSetName = "DELETE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Beta", "v1.0")]
        [string]$APIVersion = "v1.0",

        [parameter(Mandatory = $false, ParameterSetName = "GET", HelpMessage = "Specify the content type for the graph request.")]
        [parameter(Mandatory = $false, ParameterSetName = "POST")]
        [parameter(Mandatory = $false, ParameterSetName = "PATCH")]
        [parameter(Mandatory = $false, ParameterSetName = "PUT")]
        [parameter(Mandatory = $false, ParameterSetName = "DELETE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("application/json", "image/png")]
        [string]$ContentType = "application/json"
    )
    Begin {
        # Construct list as return value for handling both single and multiple instances in response from call
        $GraphResponseList = New-Object -TypeName "System.Collections.ArrayList"

        # Construct full URI
        $GraphURI = "https://graph.microsoft.com/$($APIVersion)/$($Resource)"
        Write-Output -InputObject "$($PSCmdlet.ParameterSetName) $($GraphURI)"
    }
    Process {
        # Call Graph API and get JSON response
        do {
            try {
                # Construct table of default request parameters
                $RequestParams = @{
                    "Uri" = $GraphURI
                    "Headers" = $Headers
                    "Method" = $PSCmdlet.ParameterSetName
                    "ErrorAction" = "Stop"
                    "Verbose" = $false
                }

                switch ($PSCmdlet.ParameterSetName) {
                    "POST" {
                        if ($PSBoundParameters["Body"]) {
                            $RequestParams.Add("Body", $Body)
                        }
                        if (-not([string]::IsNullOrEmpty($ContentType))) {
                            $RequestParams.Add("ContentType", $ContentType)
                        }
                    }
                    "PATCH" {
                        $RequestParams.Add("Body", $Body)
                        $RequestParams.Add("ContentType", $ContentType)
                    }
                    "PUT" {
                        $RequestParams.Add("Body", $Body)
                        $RequestParams.Add("ContentType", $ContentType)
                    }
                }

                # Invoke Graph request
                $GraphResponse = Invoke-RestMethod @RequestParams

                # Handle paging in response
                if ($GraphResponse.'@odata.nextLink' -ne $null) {
                    $GraphResponseList.AddRange($GraphResponse.value) | Out-Null
                    $GraphURI = $GraphResponse.'@odata.nextLink'
                    Write-Output -InputObject "NextLink: $($GraphURI)"
                }
                else {
                    # NextLink from response was null, assuming last page but also handle if a single instance is returned
                    if (-not([string]::IsNullOrEmpty($GraphResponse.value))) {
                        $GraphResponseList.AddRange($GraphResponse.value) | Out-Null
                    }
                    else {
                        $GraphResponseList.Add($GraphResponse) | Out-Null
                    }
                    
                    # Set graph response as handled and stop processing loop
                    $GraphResponseProcess = $false
                }
            }
            catch [System.Exception] {
                # Capture current error
                $ExceptionItem = $PSItem
                switch ($ExceptionItem.Exception.Response.StatusCode) {
                    "TooManyRequests" {
                        # Detected throttling based from response status code
                        $RetryInSeconds = $ExceptionItem.Exception.Response.Headers["Retry-After"]

                        if ($RetryInSeconds -ne $null) {
                            # Wait for given period of time specified in response headers
                            Write-Warning -Message "Graph is throttling the request, will retry in '$($RetryInSeconds)' seconds"
                            Start-Sleep -Seconds $RetryInSeconds
                        }
                        else {
                            Write-Warning -Message "Graph is throttling the request, will retry in default '300' seconds"
                            Start-Sleep -Seconds 300
                        }
                    }
                    "GatewayTimeout" {
                        Write-Warning -Message "Graph returned Gateway Timeout for the request, will retry in default '60' seconds"
                        Start-Sleep -Seconds 60
                    }
                    default {
                        # Convert status code to integer for output
                        $HttpStatusCodeInteger = ([int][System.Net.HttpStatusCode]$ExceptionItem.Exception.Response.StatusCode)
                        
                        switch ($PSCmdlet.ParameterSetName) {
                            "GET" {
                                # Output warning message that the request failed with error code
                                Write-Warning -Message "Graph request failed with status code '$($HttpStatusCodeInteger) ($($ExceptionItem.Exception.Response.StatusCode))'"
                            }
                            default {
                                # Construct new custom error record
                                $SystemException = New-Object -TypeName "System.Management.Automation.RuntimeException" -ArgumentList ("{0}: {1}" -f $ExceptionItem.Exception.Response.StatusCode, $ExceptionItem.Exception.Response)
                                $ErrorRecord = New-Object -TypeName "System.Management.Automation.ErrorRecord" -ArgumentList @($SystemException, $ErrorID, [System.Management.Automation.ErrorCategory]::NotImplemented, [string]::Empty)
    
                                # Throw a terminating custom error record
                                $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                            }
                        }
    
                        # Set graph response as handled and stop processing loop
                        $GraphResponseProcess = $false
                    }
                }
            }
        }
        until ($GraphResponseProcess -eq $false)

        # Handle return value
        return $GraphResponseList
    }
}

function Send-LogAnalyticsPayload {
    <#
    .SYNOPSIS
        Send data to Log Analytics Collector API through a web request.
        
    .DESCRIPTION
        Send data to Log Analytics Collector API through a web request.
        
    .PARAMETER WorkspaceID
        Specify the Log Analytics workspace ID.

    .PARAMETER SharedKey
        Specify either the Primary or Secondary Key for the Log Analytics workspace.

    .PARAMETER Body
        Specify a JSON representation of the data objects.

    .PARAMETER LogType
        Specify the name of the custom log in the Log Analytics workspace.

    .PARAMETER TimeGenerated
        Specify a custom date time string to be used as TimeGenerated value instead of the default.
        
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-04-20
        Updated:     2021-04-20

        Version history:
        1.0.0 - (2021-04-20) Function created
    #>  
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Log Analytics workspace ID.")]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceID,

        [parameter(Mandatory = $true, HelpMessage = "Specify either the Primary or Secondary Key for the Log Analytics workspace.")]
        [ValidateNotNullOrEmpty()]
        [string]$SharedKey,

        [parameter(Mandatory = $true, HelpMessage = "Specify a JSON representation of the data objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$Body,

        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the custom log in the Log Analytics workspace.")]
        [ValidateNotNullOrEmpty()]
        [string]$LogType,

        [parameter(Mandatory = $false, HelpMessage = "Specify a custom date time string to be used as TimeGenerated value instead of the default.")]
        [ValidateNotNullOrEmpty()]
        [string]$TimeGenerated = [string]::Empty
    )
    Process {
        # Construct header string with RFC1123 date format for authorization
        $RFC1123Date = [DateTime]::UtcNow.ToString("r")
        $Header = -join@("x-ms-date:", $RFC1123Date)

        # Convert authorization string to bytes
        $ComputeHashBytes = [Text.Encoding]::UTF8.GetBytes(-join@("POST", "`n", $Body.Length, "`n", "application/json", "`n", $Header, "`n", "/api/logs"))

        # Construct cryptographic SHA256 object
        $SHA256 = New-Object -TypeName "System.Security.Cryptography.HMACSHA256"
        $SHA256.Key = [System.Convert]::FromBase64String($SharedKey)

        # Get encoded hash by calculated hash from bytes
        $EncodedHash = [System.Convert]::ToBase64String($SHA256.ComputeHash($ComputeHashBytes))

        # Construct authorization string
        $Authorization = 'SharedKey {0}:{1}' -f $WorkspaceID, $EncodedHash

        # Construct Uri for API call
        $Uri = -join@("https://", $WorkspaceID, ".ods.opinsights.azure.com/", "api/logs", "?api-version=2016-04-01")

        # Construct headers table
        $HeaderTable = @{
            "Authorization" = $Authorization
            "Log-Type" = $LogType
            "x-ms-date" = $RFC1123Date
            "time-generated-field" = $TimeGenerated
        }

        # Invoke web request
        $WebResponse = Invoke-WebRequest -Uri $Uri -Method "POST" -ContentType "application/json" -Headers $HeaderTable -Body $Body -UseBasicParsing

        $ReturnValue = [PSCustomObject]@{
            StatusCode = $WebResponse.StatusCode
            PayloadSizeKB = ($Body.Length/1024).ToString("#.#")
        }
        
        # Handle return value
        return $ReturnValue
    }
}

function Get-AutopilotDevice {
    <#
    .SYNOPSIS
        Retrieve all Autopilot device identities.
        
    .DESCRIPTION
        Retrieve all Autopilot device identities.
        
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-04-28
        Updated:     2021-04-28

        Version history:
        1.0.0 - (2021-04-28) Function created
    #>    
    Process {
        # Retrieve all Windows Autopilot device identities
        $ResourceURI = "deviceManagement/windowsAutopilotDeviceIdentities"
        $GraphResponse = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceURI -Headers $Script:AuthToken -Verbose

        # Handle return response
        return $GraphResponse
    }
}

# Define required variables (these should be automation variables retrieved when runbook is executed)
Write-Output -InputObject "Attempting to read application settings"
$TenantID = $env:TenantID
$ClientID = $env:ClientID
$ClientSecret = $env:ClientSecret
$WorkspaceID = $env:WorkspaceID
$SharedKey = $env:SharedKey
$LogType = $env:LogType
$AutopilotDeviceBatchCount = $env:BatchCount

# Retrieve authentication token
Write-Output -InputObject "Attempting to retrieve access token for ClientID: $($ClientID)"
$Script:AuthToken = Get-AuthToken -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret

# Gather Autopilot device details
Write-Output -InputObject "Attempting to retrieve all Autopilot device identities, this could take some time"
$AutopilotDevices = Get-AutopilotDevice

# Measure detected Autopilot identities count
Write-Output -InputObject "Start calculating detected Autopilot identities"
$AutopilotIdentitiesCount = ($AutopilotDevices | Measure-Object).Count

if ($AutopilotDevices -ne $null) {
    # Construct array list for all Autopilot device identities retrieved from Graph API call
    $AutopilotDeviceList = New-Object -TypeName "System.Collections.ArrayList"

    # Construct and start a timer for output
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $AutopilotIdentitiesCurrentCount = 0
    $SecondsCount = 0

    # Process each Autopilot device identity
    foreach ($AutopilotDevice in $AutopilotDevices) {
        # Increase current progress count
        $AutopilotIdentitiesCurrentCount++

        # Handle output count for progress visibility
        if ([math]::Round($Timer.Elapsed.TotalSeconds) -gt ($SecondsCount + 30)) {
            # Increase minutes count for next output frequence
            $SecondsCount = [math]::Round($Timer.Elapsed.TotalSeconds)

            # Write output every 30 seconds
            Write-Output -InputObject "Elapsed time: $($Timer.Elapsed.Hours) hour $($Timer.Elapsed.Minutes) min $($Timer.Elapsed.Seconds) seconds"
            Write-Output -InputObject "Progress count: $($AutopilotIdentitiesCurrentCount) / $($AutopilotIdentitiesCount)"
        }

        # Construct custom object to contain current Autopilot device identity details and add it to array list
        $PSObject = [PSCustomObject]@{
            Id = $AutopilotDevice.id
            SerialNumber = $AutopilotDevice.serialNumber
            Model = $AutopilotDevice.model
            Manufacturer = $AutopilotDevice.manufacturer
            GroupTag = if (-not[string]::IsNullOrEmpty($AutopilotDevice.groupTag)) { $AutopilotDevice.groupTag } else { [string]::Empty }
            EnrollmentState = $AutopilotDevice.enrollmentState
            AzureADDeviceID = if (-not[string]::IsNullOrEmpty($AutopilotDevice.azureAdDeviceId)) { $AutopilotDevice.azureAdDeviceId } else { [string]::Empty }
            IntuneDeviceID = if (-not[string]::IsNullOrEmpty($AutopilotDevice.managedDeviceId)) { $AutopilotDevice.managedDeviceId } else { [string]::Empty }
        }
        $AutopilotDeviceList.Add($PSObject) | Out-Null
    }
    Write-Output -InputObject "Successfully processed a total of '$($AutopilotDeviceList.Count)' Autopilot identities"

    # Initiate Autopilot device identity web request to Log Analytics Collector API with a batch approach
    Write-Output -InputObject "Starting batched payload sending to Log Analytics Collector API with amounts of '$($AutopilotDeviceBatchCount)' objects in each batch"
    $AutopilotDeviceProcessedCount = 0
    do {
        # Select devices from array list based on batch count
        $AutopilotCurrentBatchObjects = $AutopilotDeviceList | Select-Object -Skip $AutopilotDeviceProcessedCount -First $AutopilotDeviceBatchCount

        # Convert current batch object to JSON
        $AutopilotCurrentBatchObjectsJSON = $AutopilotCurrentBatchObjects | ConvertTo-Json

        # Increase processed count for next batch
        $AutopilotDeviceProcessedCount = $AutopilotDeviceProcessedCount + ($AutopilotCurrentBatchObjects | Measure-Object).Count

        # Invoke web request with current batch payload
        $LogAnalyticsAPIResponse = Send-LogAnalyticsPayload -WorkspaceID $WorkspaceID -SharedKey $SharedKey -Body $AutopilotCurrentBatchObjectsJSON -LogType $LogType
        if ($LogAnalyticsAPIResponse.StatusCode -like "200") {
            Write-Output -InputObject "Successfully sent a total of '$($AutopilotCurrentBatchObjects.Count)' batched payload objects to workspace, with an overall progress of: $($AutopilotDeviceProcessedCount) / $($AutopilotDeviceList.Count)"
        }
        else {
            Write-Warning -Message "Failed to send batched payload with status code from request: $($LogAnalyticsAPIResponse.StatusCode)"
            Write-Output -InputObject "Attempting to send the current batch again with a delay of 30 seconds"

            # Attempt to send current batch again, but wait 30 seconds
            Start-Sleep -Seconds 30

            # Invoke web request with current batch payload, second attempt
            $LogAnalyticsAPIResponse = Send-LogAnalyticsPayload -WorkspaceID $WorkspaceID -SharedKey $SharedKey -Body $AutopilotCurrentBatchObjectsJSON -LogType $LogType
            if ($LogAnalyticsAPIResponse.StatusCode -like "200") {
                Write-Output -InputObject "Successfully sent a total of '$($AutopilotCurrentBatchObjects.Count)' batched payload objects to workspace, with an overall progress of: $($AutopilotDeviceProcessedCount) / $($AutopilotDeviceList.Count)"
            }
            else {
                Write-Warning -Message "Failed to send batched payload after second attempt with status code from request: $($LogAnalyticsAPIResponse.StatusCode)"
            }
        }

        # Cleanup resources for optimized memory utilization
        Remove-Variable -Name "AutopilotCurrentBatchObjects"
        Remove-Variable -Name "AutopilotCurrentBatchObjectsJSON"
        [System.GC]::Collect()
    }
    until ($AutopilotDeviceProcessedCount -ge $AutopilotDeviceList.Count)

    # Payload operation message completed
    Write-Output -InputObject "AutopilotCollector completed successfully"
}
else {
    Write-Output -InputObject "AutopilotCollector could not detect any Autopilot device identities"
}