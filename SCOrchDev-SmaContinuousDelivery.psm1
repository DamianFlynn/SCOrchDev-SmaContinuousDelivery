<#
.Synopsis
    Check GIT repository for new commits. If found sync the changes into
    the current SMA environment

.Parameter RepositoryName
#>
Function Invoke-GitRepositorySync
{
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [String]
        $RepositoryInformationJSON,

        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [String]
        $RepositoryName,

        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [pscredential]
        $Credential,

        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [string]
        $WebserviceEndpoint,

        [Parameter(
            Mandatory = $true,
            Position = 3
        )]
        [string]
        $WebservicePort = '9090'
    )
    
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "Starting [$FunctionName]"
    $StartTime = Get-Date

    Try
    {
        $RepositoryInformation = (ConvertFrom-Json -InputObject $RepositoryInformationJSON)."$RepositoryName"
        Write-Verbose -Message "`$RepositoryInformation [$(ConvertTo-Json -InputObject $RepositoryInformation)]"

        $RunbookWorker = Get-SMARunbookWorker
        
        # Update the repository on all SMA Workers
        Invoke-Command -ComputerName $RunbookWorker -Credential $Credential -ScriptBlock {
            $null = $(
                $DebugPreference       = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $VerbosePreference     = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                    
                $RepositoryInformation = $Using:RepositoryInformation
                Update-GitRepository -RepositoryInformation $RepositoryInformation
            )
        }

        $RepositoryChangeJSON = Find-GitRepositoryChange -RepositoryInformation $RepositoryInformation
        $RepositoryChange = ConvertFrom-Json -InputObject $RepositoryChangeJSON
        if("$($RepositoryChange.CurrentCommit)" -ne "$($RepositoryInformation.CurrentCommit)")
        {
            Write-Verbose -Message "Processing [$($RepositoryInformation.CurrentCommit)..$($RepositoryChange.CurrentCommit)]"
            Write-Verbose -Message "RepositoryChange [$RepositoryChangeJSON]"
            $ReturnInformationJSON = Group-RepositoryFile -Files $RepositoryChange.Files `
                                                          -RepositoryInformation $RepositoryInformation
            $ReturnInformation = ConvertFrom-Json -InputObject $ReturnInformationJSON
            Write-Verbose -Message "ReturnInformation [$ReturnInformationJSON]"
            
            Foreach($SettingsFilePath in $ReturnInformation.SettingsFiles)
            {
                Publish-SMASettingsFileChange -FilePath $SettingsFilePath `
                                              -CurrentCommit $RepositoryChange.CurrentCommit `
                                              -RepositoryName $RepositoryName
            }
            
            Foreach($ModulePath in $ReturnInformation.ModuleFiles)
            {
                Try
                {
                    $PowerShellModuleInformation = Test-ModuleManifest -Path $ModulePath
                    $ModuleName = $PowerShellModuleInformation.Name -as [string]
                    $ModuleVersion = $PowerShellModuleInformation.Version -as [string]
                    $PowerShellModuleInformation = Import-SmaPowerShellModule -ModulePath $ModulePath `
                                                                              -WebserviceEndpoint $WebserviceEndpoint `
                                                                              -WebservicePort $WebservicePort `
                                                                              -Credential $SMACred
                }
                Catch
                {
                    $Exception = New-Exception -Type 'ImportSmaPowerShellModuleFailure' `
                                               -Message 'Failed to import a PowerShell module into Sma' `
                                               -Property @{
                        'ErrorMessage' = (Convert-ExceptionToString -Exception $_) ;
                        'ModulePath' = $ModulePath ;
                        'ModuleName' = $ModuleName ;
                        'ModuleVersion' = $ModuleVersion ;
                        'PowerShellModuleInformation' = "$(ConvertTo-JSON -InputObject $PowerShellModuleInformation)" ;
                        'Credential' = $Credential.UserName ;
                    }
                    Write-Warning -Message $Exception -WarningAction Continue
                }
            }

            Foreach($RunbookFilePath in $ReturnInformation.ScriptFiles)
            {
                Publish-SMARunbookChange -FilePath $RunbookFilePath `
                                         -CurrentCommit $RepositoryChange.CurrentCommit `
                                         -RepositoryName $RepositoryName
            }
            
            if($ReturnInformation.CleanRunbooks)
            {
                Remove-SmaOrphanRunbook -RepositoryName $RepositoryName
            }
            if($ReturnInformation.CleanAssets)
            {
                Remove-SmaOrphanAsset -RepositoryName $RepositoryName
            }
            if($ReturnInformation.CleanModules)
            {
                Remove-SmaOrphanModule
            }
            if($ReturnInformation.ModuleFiles)
            {
                Try
                {
                    Write-Verbose -Message 'Validating Module Path on Runbook Wokers'
                    $RepositoryModulePath = "$($RepositoryInformation.Path)\$($RepositoryInformation.PowerShellModuleFolder)"
                    Invoke-Command -ComputerName $RunbookWorker -Credential $Credential -ScriptBlock {
                        Add-PSEnvironmentPathLocation -Path $Using:RepositoryModulePath -Location Machine
                    }
                    Write-Verbose -Message 'Finished Validating Module Path on Runbook Wokers'
                }
                Catch
                {
                    $Exception = New-Exception -Type 'PowerShellModulePathValidationError' `
                                               -Message 'Failed to set PSModulePath' `
                                               -Property @{
                        'ErrorMessage' = (Convert-ExceptionToString $_) ;
                        'RepositoryModulePath' = $RepositoryModulePath ;
                        'RunbookWorker' = $RunbookWorker ;
                    }
                    Write-Warning -Message $Exception -WarningAction Continue
                }
            }
            $UpdatedRepositoryInformation = (Update-RepositoryInformationCommitVersion -RepositoryInformation $RepositoryInformation `
                                                                                       -RepositoryName $RepositoryName `
                                                                                       -Commit $RepositoryChange.CurrentCommit) -as [string]
            Write-Verbose -Message "Finished Processing [$($RepositoryInformation.CurrentCommit)..$($RepositoryChange.CurrentCommit)]"
        }
    }
    Catch
    {
        Write-Exception -Stream Warning -Exception $_
    }
    Write-CompletedMessage -StartTime $StartTime -Name $FunctionName

    Return (Select-FirstValid -Value @($UpdatedRepositoryInformation, $RepositoryInformationJSON))
}

<#
    .Synopsis
        Takes a ps1 file and publishes it to the current SMA environment.
    
    .Parameter FilePath
        The full path to the script file

    .Parameter CurrentCommit
        The current commit to store this version under

    .Parameter RepositoryName
        The name of the repository that will be listed as the 'owner' of this
        runbook
#>
Function Publish-SMARunbookChange
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $FilePath,

        [Parameter(Mandatory=$True)]
        [String]
        $CurrentCommit,

        [Parameter(Mandatory=$True)]
        [String]
        $RepositoryName,

        [Parameter(Mandatory=$True)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [string]
        $WebserviceEndpoint = 'https://localhost',

        [Parameter(Mandatory=$False)]
        [string]
        $WebservicePort = '9090'
    )
    
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "[$FilePath] Starting [$FunctionName]"
    $StartTime = Get-Date

    Try
    {
        $WorkflowName = Get-WorkflowNameFromFile -FilePath $FilePath
        
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        $Runbook = Get-SmaRunbook -Name $WorkflowName `
                                  -WebServiceEndpoint $WebserviceEndpoint `
                                  -Port $WebservicePort `
                                  -Credential $Credential
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

        if($Runbook -as [bool])
        {
            Write-Verbose -Message "[$WorkflowName] Initial Import"
            
            $Runbook = Import-SmaRunbook -Path $FilePath `
                                         -WebServiceEndpoint $WebserviceEndpoint `
                                         -Port $WebservicePort `
                                         -Credential $Credential
            
            $TagLine = "RepositoryName:$RepositoryName;CurrentCommit:$CurrentCommit;"
            $NewVersion = $True
        }
        else
        {
            Write-Verbose -Message "[$WorkflowName] Update"
            $TagUpdateJSON = New-ChangesetTagLine -TagLine $Runbook.Tags `
                                                  -CurrentCommit $CurrentCommit `
                                                  -RepositoryName $RepositoryName
            $TagUpdate = ConvertFrom-Json $TagUpdateJSON
            $TagLine = $TagUpdate.TagLine
            $NewVersion = $TagUpdate.NewVersion
            if($NewVersion)
            {
                $EditStatus = Edit-SmaRunbook -Overwrite `
                                              -Path $FilePath `
                                              -Name $WorkflowName `
                                              -WebServiceEndpoint $WebserviceEndpoint `
                                              -Port $WebservicePort `
                                              -Credential $Credential
            }
            else
            {
                Write-Verbose -Message "[$WorkflowName] Already is at commit [$CurrentCommit]"
            }
        }
        if($NewVersion)
        {
            $PublishHolder = Publish-SmaRunbook -Name $WorkflowName `
                                                -WebServiceEndpoint $WebserviceEndpoint `
                                                -Port $WebservicePort `
                                                -Credential $Credential

            Set-SmaRunbookTags -RunbookID $Runbook.RunbookID.Guid `
                               -Tags $TagLine `
                               -WebserviceEndpoint $WebserviceEndpoint `
                               -Port $WebservicePort `
                               -Credential $Credential
        }
    }
    Catch
    {
        Write-Exception -Stream Warning -Exception $_
    }
    Write-CompletedMessage -StartTime $StartTime -Name "[$FunctionName] [$FilePath]"
}

<#
.Synopsis
    Takes a json file and publishes all schedules and variables from it into SMA
    
.Parameter FilePath
    The path to the settings file to process

.Parameter CurrentCommit
    The current commit to tag the variables and schedules with

.Parameter RepositoryName
    The Repository Name that will 'own' the variables and schedules
#>
Function Publish-SMASettingsFileChange
{
    Param( 
        [Parameter(Mandatory = $True)]
        [String] 
        $FilePath,
        
        [Parameter(Mandatory = $True)]
        [String]
        $CurrentCommit,

        [Parameter(Mandatory = $True)]
        [String]
        $RepositoryName,

        [Parameter(Mandatory=$True)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [string]
        $WebserviceEndpoint = 'https://localhost',

        [Parameter(Mandatory=$False)]
        [string]
        $WebservicePort = '9090'
    )
    
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "[$FilePath] Starting [$FunctionName]"
    $StartTime = Get-Date

    Try
    {
        $VariablesJSON = Get-GlobalFromFile -FilePath $FilePath -GlobalType Variables
        $Variables = $VariablesJSON | ConvertFrom-JSON | ConvertFrom-PSCustomObject
        foreach($VariableName in ($Variables.Keys -as [array]))
        {
            Try
            {
                Write-Verbose -Message "[$VariableName] Updating"
                $Variable = $Variables."$VariableName"
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $SmaVariable = Get-SmaVariable -Name $VariableName `
                                               -WebServiceEndpoint $WebserviceEndpoint `
                                               -Port $WebservicePort `
                                               -Credential $Credential
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                if($SmaVariable -as [bool])
                {
                    Write-Verbose -Message "[$($VariableName)] is a New Variable"
                    $VariableDescription = "$($Variable.Description)`n`r__RepositoryName:$($RepositoryName);CurrentCommit:$($CurrentCommit);__"
                    $NewVersion = $True
                }
                else
                {
                    Write-Verbose -Message "[$($VariableName)] is an existing Variable"
                    $TagUpdateJSON = New-ChangesetTagLine -TagLine $SmaVariable.Description`
                                                          -CurrentCommit $CurrentCommit `
                                                          -RepositoryName $RepositoryName
                    $TagUpdate = ConvertFrom-Json -InputObject $TagUpdateJSON
                    $VariableDescription = "$($TagUpdate.TagLine)"
                    $NewVersion = $TagUpdate.NewVersion
                }
                if($NewVersion)
                {
                    $SmaVariableParameters = @{
                        'Name' = $VariableName ;
                        'Value' = $Variable.Value ;
                        'Description' = $VariableDescription ;
                        'WebServiceEndpoint' = $WebserviceEndpoint ;
                        'Port' = $WebservicePort ;
                        'Credential' = $Credential ;
                        'Force' = $True ;
                    }
                    if($Variable.isEncrypted -as [bool])
                    {
                        $null = $SmaVariableParameters.Add('Encrypted',$True)
                        $CreateEncryptedVariable = Set-SmaVariable @SmaVariableParameters `
                                                                   -Encrypted
                    }
                    $null = Set-SmaVariable @SmaVariableParameters
                }
                else
                {
                    Write-Verbose -Message "[$($VariableName)] Is not a new version. Skipping"
                }
                Write-Verbose -Message "[$($VariableName)] Finished Updating"
            }
            Catch
            {
                $Exception = New-Exception -Type 'VariablePublishFailure' `
                                           -Message 'Failed to publish a variable to SMA' `
                                           -Property @{
                    'ErrorMessage' = Convert-ExceptionToString $_ ;
                    'VariableName' = $VariableName ;
                }
                Write-Warning -Message $Exception -WarningAction Continue
            }
        }
        $SchedulesJSON = Get-GlobalFromFile -FilePath $FilePath -GlobalType Schedules
        $Schedules = $SchedulesJSON | ConvertFrom-JSON | ConvertFrom-PSCustomObject
        foreach($ScheduleName in $Schedules.Keys)
        {
            Write-Verbose -Message "[$ScheduleName] Updating"
            try
            {
                $Schedule = $Schedules."$ScheduleName"
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $SmaSchedule = Get-SmaSchedule -Name $ScheduleName `
                                               -WebServiceEndpoint $WebserviceEndpoint `
                                               -Port $WebservicePort `
                                               -Credential $Credential
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                if($SmaSchedule -as [bool])
                {
                    Write-Verbose -Message "[$($ScheduleName)] is a New Schedule"
                    $ScheduleDescription = "$($Schedule.Description)`n`r__RepositoryName:$($RepositoryName);CurrentCommit:$($CurrentCommit);__"
                    $NewVersion = $True
                }
                else
                {
                    Write-Verbose -Message "[$($ScheduleName)] is an existing Schedule"
                    $TagUpdateJSON = New-ChangesetTagLine -TagLine $SmaVariable.Description`
                                                          -CurrentCommit $CurrentCommit `
                                                          -RepositoryName $RepositoryName
                    $TagUpdate = ConvertFrom-Json -InputObject $TagUpdateJSON
                    $ScheduleDescription = "$($TagUpdate.TagLine)"
                    $NewVersion = $TagUpdate.NewVersion
                }
                if($NewVersion)
                {
                    $CreateSchedule = Set-SmaSchedule -Name $ScheduleName `
                                                      -Description $ScheduleDescription `
                                                      -ScheduleType DailySchedule `
                                                      -DayInterval $Schedule.DayInterval `
                                                      -StartTime $Schedule.NextRun `
                                                      -ExpiryTime $Schedule.ExpirationTime `
                                                      -WebServiceEndpoint $WebserviceEndpoint `
                                                      -Port $WebservicePort `
                                                      -Credential $Credential

                    if(Test-IsNullOrEmpty -String $CreateSchedule)
                    {
                        Throw-Exception -Type 'ScheduleFailedToCreate' `
                                        -Message 'Failed to create the schedule' `
                                        -Property @{
                            'ScheduleName'     = $ScheduleName
                            'Description'      = $ScheduleDescription
                            'ScheduleType'     = 'DailySchedule'
                            'DayInterval'      = $Schedule.DayInterval
                            'StartTime'        = $Schedule.NextRun
                            'ExpiryTime'       = $Schedule.ExpirationTime
                            'WebServiceEndpoint' = $WebserviceEndpoint
                            'Port'             = $WebservicePort
                            'Credential'       = $Credential.UserName
                        }
                    }
                    try
                    {
                        $Parameters   = ConvertFrom-PSCustomObject -InputObject $Schedule.Parameter `
                                                                   -MemberType NoteProperty `
                        $RunbookStart = Start-SmaRunbook -Name $Schedule.RunbookName `
                                                         -ScheduleName $ScheduleName `
                                                         -WebServiceEndpoint $WebserviceEndpoint `
                                                         -Port $WebservicePort `
                                                         -Parameters $Parameters `
                                                         -Credential $Credential
                        if(Test-IsNullOrEmpty -String $RunbookStart)
                        {
                            Throw-Exception -Type 'ScheduleFailedToSet' `
                                            -Message 'Failed to set the schedule on the target runbook' `
                                            -Property @{
                                'ScheduleName' = $ScheduleName
                                'RunbookName' = $Schedule.RunbookName
                                'Parameters' = $(ConvertTo-Json -InputObject $Parameters)
                            }
                        }
                    }
                    catch
                    {
                        Remove-SmaSchedule -Name $ScheduleName `
                                           -WebServiceEndpoint $WebserviceEndpoint `
                                           -Port $WebservicePort `
                                           -Credential $Credential `
                                           -Force
                        Write-Exception -Exception $_ -Stream Warning
                    }
                }
            }
            catch
            {
                Write-Exception -Exception $_ -Stream Warning
            }
            Write-Verbose -Message "[$($ScheduleName)] Finished Updating"
        }
    }
    Catch
    {
        Write-Exception -Stream Warning -Exception $_
    }
    Write-CompletedMessage -StartTime $StartTime -Name "[$FunctionName] [$FilePath]"
}

<#
.Synopsis
    Checks a SMA environment and removes any global assets tagged
    with the current repository that are no longer found in
    the repository

.Parameter RepositoryName
    The name of the repository
#>
Function Remove-SmaOrphanAsset
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $RepositoryInfoJSON,
        
        [Parameter(Mandatory=$True)]
        [string]
        $RepositoryName,

        [Parameter(Mandatory=$True)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [string]
        $WebserviceEndpoint = 'https://localhost',

        [Parameter(Mandatory=$False)]
        [string]
        $WebservicePort = '9090'
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "Starting [$FunctionName]"
    $StartTime = Get-Date

    Try
    {
        $RepositoryInformation = $RepositoryInfoJSON | ConvertFrom-Json

        $SmaVariables = Get-SmaVariable -WebServiceEndpoint $WebserviceEndpoint `
                                        -Port $WebservicePort `
                                        -Credential $Credential
        if($SmaVariables) 
        {
            $SmaVariableTable = Group-AssetsByRepository -InputObject $SmaVariables 
        }

        $SmaSchedules = Get-SmaSchedule -WebServiceEndpoint $WebserviceEndpoint `
                                        -Port $WebservicePort `
                                        -Credential $Credential
        if($SmaSchedules) 
        {
            $SmaScheduleTable = Group-AssetsByRepository -InputObject $SmaSchedules 
        }

        $RepositoryAssets = Get-GitRepositoryAssetName -Path "$($RepositoryInformation.Path)\$($RepositoryInformation.RunbookFolder)"

        if($SmaVariableTable."$RepositoryName")
        {
            $VariableDifferences = Compare-Object -ReferenceObject $SmaVariableTable."$RepositoryName".Name `
                                                  -DifferenceObject $RepositoryAssets.Variable
            Foreach($Difference in $VariableDifferences)
            {
                Try
                {
                    if($Difference.SideIndicator -eq '<=')
                    {
                        Write-Verbose -Message "[$($Difference.InputObject)] Does not exist in Source Control"
                        Remove-SmaVariable -Name $Difference.InputObject `
                                           -WebServiceEndpoint $WebserviceEndpoint `
                                           -Port $WebservicePort `
                                           -Credential $Credential
                        Write-Verbose -Message "[$($Difference.InputObject)] Removed from SMA"
                    }
                }
                Catch
                {
                    $Exception = New-Exception -Type 'RemoveSmaAssetFailure' `
                                                -Message 'Failed to remove a Sma Asset' `
                                                -Property @{
                        'ErrorMessage' = (Convert-ExceptionToString -Exception $_) ;
                        'AssetName' = $Difference.InputObject ;
                        'AssetType' = 'Variable' ;
                        'WebserviceEnpoint' = $WebserviceEndpoint ;
                        'Port' = $WebservicePort ;
                        'Credential' = $Credential.UserName ;
                    }
                    Write-Warning -Message $Exception -WarningAction Continue
                }
            }
        }
        else
        {
            Write-Warning -Message "[$RepositoryName] No Variables found in environment for this repository" `
                          -WarningAction Continue
        }

        if($SmaScheduleTable."$RepositoryName")
        {
            $ScheduleDifferences = Compare-Object -ReferenceObject $SmaScheduleTable."$RepositoryName".Name `
                                                  -DifferenceObject $RepositoryAssets.Schedule
            Foreach($Difference in $ScheduleDifferences)
            {
                Try
                {
                    if($Difference.SideIndicator -eq '<=')
                    {
                        Write-Verbose -Message "[$($Difference.InputObject)] Does not exist in Source Control"
                        Remove-SmaSchedule -Name $Difference.InputObject `
                                           -WebServiceEndpoint $WebserviceEndpoint `
                                           -Port $WebservicePort `
                                           -Credential $Credential
                        Write-Verbose -Message "[$($Difference.InputObject)] Removed from SMA"
                    }
                }
                Catch
                {
                    $Exception = New-Exception -Type 'RemoveSmaAssetFailure' `
                                                -Message 'Failed to remove a Sma Asset' `
                                                -Property @{
                        'ErrorMessage' = (Convert-ExceptionToString $_) ;
                        'AssetName' = $Difference.InputObject ;
                        'AssetType' = 'Schedule' ;
                        'WebserviceEnpoint' = $WebserviceEndpoint ;
                        'Port' = $WebservicePort ;
                        'Credential' = $Credential.UserName ;
                    }
                    Write-Exception -Exception $Exception -Stream Warning
                }
            }
        }
        else
        {
            Write-Warning -Message "[$RepositoryName] No Schedules found in environment for this repository" `
                          -WarningAction Continue
        }
    }
    Catch
    {
        $Exception = New-Exception -Type 'RemoveSmaOrphanAssetWorkflowFailure' `
                                   -Message 'Unexpected error encountered in the Remove-SmaOrphanAsset workflow' `
                                   -Property @{
            'ErrorMessage' = (Convert-ExceptionToString $_) ;
            'RepositoryName' = $RepositoryName ;
        }
        Write-Exception -Exception $Exception -Stream Warning
    }
    Write-CompletedMessage -StartTime $StartTime -Name $FunctionName
}

<#
    .Synopsis
        Checks a SMA environment and removes any modules that are not found
        in the local psmodulepath
#>
Function Remove-SmaOrphanModule
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $RepositoryName,

        [Parameter(Mandatory=$True)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [string]
        $WebserviceEndpoint = 'https://localhost',

        [Parameter(Mandatory=$False)]
        [string]
        $WebservicePort = '9090'
    
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "Starting [$FunctionName]"
    $StartTime = Get-Date
    Try
    {
        $SmaModule = Get-SmaModule -WebServiceEndpoint $WebserviceEndpoint `
                                   -Port $WebservicePort `
                                   -Credential $Credential

        $LocalModule = Get-Module -ListAvailable -Refresh -Verbose:$false

        if(-not ($SmaModule -and $LocalModule))
        {
            if(-not $SmaModule)   { Write-Warning -Message 'No modules found in SMA. Not cleaning orphan modules' -WarningAction Continue }
            if(-not $LocalModule) { Write-Warning -Message 'No modules found in local PSModule Path. Not cleaning orphan modules' -WarningAction Continue }
        }
        else
        {
            $ModuleDifference = Compare-Object -ReferenceObject  $SmaModule.ModuleName `
                                               -DifferenceObject $LocalModule.Name
            Foreach($Difference in $ModuleDifference)
            {
                if($Difference.SideIndicator -eq '<=')
                {
                    Try
                    {
                        Write-Verbose -Message "[$($Difference.InputObject)] Does not exist in Source Control"
                        <#
                        TODO: Investigate / Test before uncommenting. Potential to brick an environment

                        Remove-SmaModule -Name $Difference.InputObject `
                                         -WebServiceEndpoint $CIVariables.WebserviceEndpoint `
                                         -Port $CIVariables.WebservicePort `
                                         -Credential $SMACred
                        #>
                        Write-Verbose -Message "[$($Difference.InputObject)] Removed from SMA"
                    }
                    Catch
                    {
                        $Exception = New-Exception -Type 'RemoveSmaModuleFailure' `
                                                   -Message 'Failed to remove a Sma Module' `
                                                   -Property @{
                            'ErrorMessage' = (Convert-ExceptionToString $_) ;
                            'RunbookName' = $Difference.InputObject ;
                            'WebserviceEnpoint' = $CIVariables.WebserviceEndpoint ;
                            'Port' = $CIVariables.WebservicePort ;
                            'Credential' = $SMACred.UserName ;
                        }
                        Write-Warning -Message $Exception -WarningAction Continue
                    }
                }
            }
        }
    }
    Catch
    {
        $Exception = New-Exception -Type 'RemoveSmaOrphanModuleWorkflowFailure' `
                                   -Message 'Unexpected error encountered in the Remove-SmaOrphanModule workflow' `
                                   -Property @{
            'ErrorMessage' = (Convert-ExceptionToString $_) ;
            'RepositoryName' = $RepositoryName ;
        }
        Write-Exception -Exception $Exception -Stream Warning
    }
    
    Write-CompletedMessage -StartTime $StartTime -Name $FunctionName
}

<#
    .Synopsis
        Checks a SMA environment and removes any runbooks tagged
        with the current repository that are no longer found in
        the repository

    .Parameter RepositoryName
        The name of the repository
#>
Function Remove-SmaOrphanRunbook
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $RepositoryInfoJSON,
        
        [Parameter(Mandatory=$True)]
        [string]
        $RepositoryName,

        [Parameter(Mandatory=$True)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$False)]
        [string]
        $WebserviceEndpoint = 'https://localhost',

        [Parameter(Mandatory=$False)]
        [string]
        $WebservicePort = '9090'
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    $FunctionName = (Get-PSCallStack)[0].Command
    Write-Verbose -Message "Starting [$FunctionName]"
    $StartTime = Get-Date

    Try
    {
        $RepositoryInformation = (ConvertFrom-JSON -InputObject $RepositoryInfoJSON)."$RepositoryName"

        $SmaRunbooks = Get-SMARunbookPaged -WebserviceEndpoint $WebserviceEndpoint `
                                           -Port $WebservicePort `
                                           -Credential $Credential
        if($SmaRunbooks) { $SmaRunbookTable = Group-RunbooksByRepository -InputObject $SmaRunbooks }
        $RepositoryWorkflows = Get-GitRepositoryWorkflowName -Path "$($RepositoryInformation.Path)\$($RepositoryInformation.RunbookFolder)"
        $Differences = Compare-Object -ReferenceObject $SmaRunbookTable.$RepositoryName.RunbookName `
                                      -DifferenceObject $RepositoryWorkflows
    
        Foreach($Difference in $Differences)
        {
            if($Difference.SideIndicator -eq '<=')
            {
                Try
                {
                    Write-Verbose -Message "[$($Difference.InputObject)] Does not exist in Source Control"
                    Remove-SmaRunbook -Name $Difference.InputObject `
                                      -WebServiceEndpoint $WebserviceEndpoint `
                                      -Port $WebservicePort `
                                      -Credential $Credential
                    Write-Verbose -Message "[$($Difference.InputObject)] Removed from SMA"
                }
                Catch
                {
                    $Exception = New-Exception -Type 'RemoveSmaRunbookFailure' `
                                               -Message 'Failed to remove a Sma Runbook' `
                                               -Property @{
                        'ErrorMessage' = (Convert-ExceptionToString $_) ;
                        'RunbookName' = $Difference.InputObject ;
                        'WebserviceEnpoint' = $WebserviceEndpoint ;
                        'Port' = $WebservicePort ;
                        'Credential' = $Credential.UserName ;
                    }
                    Write-Warning -Message $Exception -WarningAction Continue
                }
            }
        }
    }
    Catch
    {
        $Exception = New-Exception -Type 'RemoveSmaOrphanRunbookWorkflowFailure' `
                                   -Message 'Unexpected error encountered in the Remove-SmaOrphanRunbook workflow' `
                                   -Property @{
            'ErrorMessage' = (Convert-ExceptionToString $_) ;
            'RepositoryName' = $RepositoryName ;
        }
        Write-Exception -Exception $Exception -Stream Warning
    }
    Write-Verbose -Message "Finished [$WorkflowCommandName]"
}
Export-ModuleMember -Function * -Verbose:$false -Debug:$False