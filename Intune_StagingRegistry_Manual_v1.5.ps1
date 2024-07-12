###############################################
### Create Registry Folders for Intune Apps ###
###############################################

#Created By: Ryan Carlson
#Updated On: 10/20/23

# -------------------------------------------------------- Version Infomation ------------------------------------------------------------ #
# v1.0 | Create Script to create proper registry folders for all other Intune apps
# v1.1 | Added part to change file permissions on ProgramData folder, so that future intune apps can delete old data
# v1.2 | Added portion to install Microsoft Graph Powershell module and changed Root folder to be "CQMedical"
# v1.3 | Added parameter for name of top-level folder
# v1.4 | Removed installation of powershell module, will create new app for that
# v1.5 | added switch to create foundation under HKEY_CURRENT_USER
# ---------------------------------------------------------------------------------------------------------------------------------------- #

param(
    [switch]$log=$false,
    [string]$FolderName = 'CQMedical',
    [switch]$user = $false,
    [string]$version = '1.5'
)

# ------------------------------------------------------- Variables ----------------------------------------------------------------------- #
#Version Info
    #$version = '1.0'
#Default Qfix Folder for Intune Apps
    $loc_ProgData = 'C:\ProgramData\' + $FolderName
    $AppName = 'IntuneRegistry_Foundation'
#Path to Registry Folder
    $loc_Reg = 'HKLM:\SOFTWARE\' + $FolderName
    $loc_User_Reg = 'HKCU:\SOFTWARE\' + $FolderName
# ----------------------------------------------------------------------------------------------------------------------------------------- #

#Start script
    #Create Qfix ProgramData Folder
        if(Test-Path -Path $loc_ProgData -ErrorAction SilentlyContinue){
            Write-Host "ProgramData Folder already exisits" -ForegroundColor Green
        }Else{
            Write-Host "ProgramData Folder does not exsits... Creating Folder" -ForegroundColor Yellow
            New-Item -Path $loc_ProgData -ItemType Directory
        }        
    #Start Logging
        if($log){
            Start-Transcript -Path $loc_ProgData\$AppName\$AppName'_Transcript.txt' -Force
        }
    #Start Registry Staging (USER)
        if($user){
            #Create Folder in Registry
                Write-Host "Creating Registry folder under SOFTWARE"
                New-Item -Path $loc_User_Reg -ItemType Directory
            #Create SubFolders in Registry
                Write-Host "Creating Folders under Registry Folder"
                New-Item -Path $loc_User_Reg -Name 'Apps' -ItemType Directory
                New-Item -Path $loc_User_Reg -Name 'Scripts' -ItemType Directory
                New-Item -Path $loc_User_Reg -Name 'Tasks' -ItemType Directory
            #Set verison of Qfix Folder
                Write-Host "Adding Values to Registry Folder"
                Set-ItemProperty -Path $loc_User_Reg -Name 'install date' -Value (Get-Date -Format "MM/dd/yyyy") -Type String
            #Check if registry folder was created
                if(Test-Path $loc_User_Reg -ErrorAction SilentlyContinue){
                    Write-Host "Registry & Filesystem have been sucessfully created"
                    Set-ItemProperty -Path $loc_User_Reg -Name 'version' -Value $version -Type String
                }
        }
    #Start Registry Staging (SYSTEM)
        if(-not($user)){
            #Create Qfix Folder in Registry
                Write-Host "Creating Registry folder under SOFTWARE"
                New-Item -Path $loc_Reg -ItemType Directory
            #Create SubFolders in Registry
                Write-Host "Creating Folders under Registry Folder"
                New-Item -Path $loc_Reg -Name 'Apps' -ItemType Directory
                New-Item -Path $loc_Reg -Name 'Scripts' -ItemType Directory
                New-Item -Path $loc_Reg -Name 'Tasks' -ItemType Directory
            #Set verison of Qfix Folder
                Write-Host "Adding Values to Registry Folder"
                Set-ItemProperty -Path $loc_Reg -Name 'install date' -Value (Get-Date -Format "MM/dd/yyyy") -Type String
            #Apply Permissions for Users to Edit Keys
                Write-Host "Applying Proper Permissions to Newly Created Registry Folder"
                #Apply New Rule
                    $idRef = [System.Security.Principal.NTAccount]("BUILTIN\Users")
                    $regRights = [System.Security.AccessControl.RegistryRights]::FullControl
                    $inhFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
                    $prFlags = [System.Security.AccessControl.PropagationFlags]::None
                    $acType = [System.Security.AccessControl.AccessControlType]::Allow
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
                    $acl = Get-Acl $loc_Reg
                    $acl.AddAccessRule($rule)
                    $acl.SetAccessRule($rule)
                    $acl | Set-Acl -Path $loc_Reg
            #Apply Permissions for Users to Edit ProgData
                Write-Host "Applying Proper Permissions to Newly Created ProgramData Folder"
                #Create new rule
                    $FileAccessList = "BUILTIN\Users", "Modify","ContainerInherit,ObjectInherit","None","Allow" 
                    $FileAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FileAccessList
                #Apply New Rule
                    $ACL = Get-ACL -Path $loc_ProgData
                    $ACL.SetAccessRule($FileAccessRule)
                    $ACL | Set-Acl $loc_ProgData
            #Check if ACL have been applied
                $Reg_ACL = Get-ACL -Path $loc_Reg | Select-Object -ExpandProperty Access | Where-Object IdentityReference -eq "BUILTIN\Users" | Where-Object RegistryRights -eq "FullControl"
                $ProgData_ACL = Get-ACL -Path $loc_ProgData | Select-Object -ExpandProperty Access | Where-Object IdentityReference -eq "BUILTIN\Users" | Where-Object FileSystemRights -eq "Modify, Synchronize"
                if(($Reg_ACL.AccessControlType -eq 'Allow') -and ($ProgData_ACL.AccessControlType -eq 'Allow')){
                    Write-Host "Registry & Filesystem rights have been sucessfully changed"
                    Set-ItemProperty -Path $loc_Reg -Name 'version' -Value $version -Type String
                }
        }
    #Stop Logging
        if($log){
            Stop-Transcript
        }
        