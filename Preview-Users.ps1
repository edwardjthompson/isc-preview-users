function Get-AccessToken {
    param (
        [String]$tenant,
        [String]$clientID,
        [String]$clientSecret,
        [String]$domain = "identitynow"
    )
    $params = @{
        uri    = "https://$tenant.api.$domain.com/oauth/token?grant_type=client_credentials&client_id=$($clientID)&client_secret=$($clientSecret)"
        method = "POST"
    }
    return (Invoke-RestMethod @params).access_token
}

function Get-UserId {
    param (
        [String]$uid,
        [String]$tenant,
        [String]$domain = "identitynow",
        [String]$token = $null
    )
    $query = "attributes.uid:""$uid"""
    $body = @{
        indices     = @("identities")
        query       = @{
            query = $query
        }
    }
    $params = @{
        method                  = "POST"
        uri                     = "https://$($tenant).api.$domain.com/v3/search"
        body                    = (ConvertTo-Json $body)
        headers                 = @{Authorization = "Bearer $token" }
        ContentType             = "application/json"
        ResponseHeadersVariable = "responseHeader"
    }
    $response = Invoke-RestMethod @params
    return $response[0].id
}

function Get-Users {
    param (
        [String]$tenant,
        [String]$domain,
        [String]$token,
        [String]$identityProfileName,
        [String[]]$users,
        [String[]]$keys,
        [bool]$refresh = $true
    )

    $maxLength = 0
    foreach ($key in $keys) {
        if ($key.Length -gt $maxLength) {
            $maxLength = $key.Length
        }
    }
    
    $loop = $true

    if ($refresh) {
        $ids = @{}
        foreach ($user in $users) {
            $ids[$user] = Get-UserId -uid $user -tenant $tenant -domain $domain -token $token
        }
    }

    $profileParams = @{
        method      = "GET"
        uri         = "https://$($tenant).api.$domain.com/v3/identity-profiles?filters=name eq ""$identityProfileName"""
        headers     = @{ Authorization = "Bearer $token" }
        ContentType = "application/json"
    }
    $color = "Green"
    do {
        if ($refresh) {
            $identityProfile = (Invoke-RestMethod @profileParams)[0]
        }
        foreach ($user in $ids.GetEnumerator()) {
            $body = [PSCustomObject]@{
                identityId              = $user.value
                identityAttributeConfig = $identityProfile.identityAttributeConfig
            }
        
            $params = @{
                method      = "POST"
                body        = (ConvertTo-Json $body -depth 100)
                uri         = "https://$($tenant).api.$domain.com/v3/identity-profiles/identity-preview"
                headers     = @{ Authorization = "Bearer $token" }
                ContentType = "application/json"
            }
            $preview = Invoke-RestMethod @params
            $values = $preview.previewAttributes | Where-Object -Property name -in $keys
            foreach ($item in $values) {
                $attribute = $item.name.PadLeft($maxLength)
                if ($item.errorMessages) {
                    Write-Host "[$($user.name)][$attribute]$($item.errorMessages.text)" -ForegroundColor Red
                }
                else {
                    Write-Host "[$($user.name)][$attribute]$($item.value)" -ForegroundColor $color
                }
            }
            if ($color -eq "Green") {
                $color = "Blue"
            }
            else {
                $color = "Green"
            }
        }
    } until (!$loop)
}

# Enter all parameters here
$tenant = 'devrel-ga-5699'
$domain = 'identitynow-demo'
$token = ''
$clientID = '<CLIENT_ID>'
$clientSecret = '<CLIENT_SECRET>'
$identityProfileName = "Systems as a Service"

# Enter the uids of users to preview
$users = @(
    "luke"
)

# Enter the technical name of Identity Attributes
$keys = @(
    "displayName"
    "email"
    "tempEmail"
    "cloudLifecycleState"
    "tempLifecycleState"
    "department"
    "tempDepartment"
)

if (!($token -or ($clientID -and $clientSecret))) {
    Write-Host "Please provide either a token or PAT details in the script"
    Exit
}
    
if (!$token) {
    $token = Get-AccessToken -tenant $tenant -clientID $clientID -clientSecret $clientSecret -domain $domain
}

Get-Users -tenant $tenant -domain $domain -token $token -identityProfileName $identityProfileName -users $users -keys $keys