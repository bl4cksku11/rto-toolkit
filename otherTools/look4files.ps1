<#
.SYNOPSIS
    Recursively search C:\ for files named hwoever your target file is names and log the results.

.NOTES
    Run from an elevated PowerShell session if possible;
    otherwise some folders may be skipped due to permissions.
#>

# -------- CONFIG --------
$StartPath   = 'C:\'                      # Root folder to start the search
$TargetName  = 'FILE_NAME'                # Exact file name, enter file name
$LogFile     = "$env:USERPROFILE\result_locations.txt"
# ------------------------

Write-Host "`nSearching $StartPath for '$TargetName' ...`n"

try {
    # -Recurse traverses all sub-directories; -ErrorAction handles access-denied cases quietly
    $results = Get-ChildItem -Path $StartPath -Filter $TargetName -Recurse -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Unexpected error during search: $_"
    exit 1
}

if ($results.Count -eq 0) {
    Write-Host "No matches found." -ForegroundColor Yellow
} else {
    # Show results on screen
    $results.FullName | ForEach-Object { Write-Host $_ }

    # Save to file
    $results.FullName | Set-Content -Path $LogFile -Encoding UTF8
    Write-Host "`nSaved $($results.Count) path(s) to $LogFile" -ForegroundColor Green
}
