<#
.SYNOPSIS
Script to audit software installed on remote computers within the domain.

.DESCRIPTION
This script remotely connects to computers in the domain and gathers information about the
installed software, including the name, version, and vendor. The results are saved to a CSV file.

.PARAMETER ComputerName
An array of computer names to scan. You can provide a single name or the path to a text file
containing a list of computer names.

.PARAMETER OutputFile
The path to the CSV file where the results will be saved.

.EXAMPLE
.\Get-InstalledSoftwareAudit.ps1 -ComputerName "Server01, PC-User1" -OutputFile "C:\Reports\SoftwareAudit.csv"

.EXAMPLE
.\Get-InstalledSoftwareAudit.ps1 -ComputerName "C:\Temp\Computers.txt" -OutputFile "\\Server02\Share\SoftwareAudit.csv"
#>
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("Computer")]
    [string[]]$ComputerName,

    [Parameter(Mandatory=$true)]
    [string]$OutputFile
)

BEGIN {
    Write-Host "Starting software audit..." -ForegroundColor Yellow
    $Results = @()
}

PROCESS {
    foreach ($Computer in $ComputerName) {
        Write-Host "Processing computer: $Computer" -ForegroundColor Cyan

        try {
            # Get installed software using Get-Package (available from PowerShell 5.0)
            $Software = Get-Package -ComputerName $Computer -ErrorAction Stop | Select-Object Name, Version, ProviderName

            if ($Software) {
                foreach ($App in $Software) {
                    $Results += [PSCustomObject]@{
                        ComputerName = $Computer
                        Name         = $App.Name
                        Version      = $App.Version
                        Vendor       = $App.ProviderName
                    }
                }
            } else {
                Write-Warning "No installed software found on computer: $Computer (Get-Package might not be available)."

                # Alternative method to retrieve information from the registry (works on older PowerShell versions)
                $RegistryPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                $SoftwareRegistry = Get-ItemProperty -Path "Registry::\\$Computer\$RegistryPath" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.DisplayName -ne $null } |
                                    Select-Object @{Name="Name";Expression={$_.DisplayName}},
                                                  @{Name="Version";Expression={$_.DisplayVersion}},
                                                  @{Name="Vendor";Expression={$_.Publisher}}

                if ($SoftwareRegistry) {
                    foreach ($App in $SoftwareRegistry) {
                        $Results += [PSCustomObject]@{
                            ComputerName = $Computer
                            Name         = $App.Name
                            Version      = $App.Version
                            Vendor       = $App.Vendor
                        }
                    }
                } else {
                    Write-Warning "Failed to retrieve software information from the registry on computer: $Computer."
                }
            }

        } catch {
            Write-Error "An error occurred while processing computer $Computer: $($_.Exception.Message)"
        }
    }
}

END {
    if ($Results.Count -gt 0) {
        # Save the results to a CSV file
        $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Audit completed. Results saved to file: $OutputFile" -ForegroundColor Green
    } else {
        Write-Host "Audit completed. No software information found." -ForegroundColor Yellow
    }
}
