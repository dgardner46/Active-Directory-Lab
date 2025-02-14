# PowerShell script to set up an Active Directory lab environment

# Install required Windows features
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote the server to a domain controller
$domainName = "LabDomain.local"
$netbiosName = "LabDomain"
Install-ADDSForest -DomainName $domainName -DomainNetbiosName $netbiosName -Force -Confirm:$false

# Create Organizational Units
New-ADOrganizationalUnit -Name "Users" -Path "DC=LabDomain,DC=local"
New-ADOrganizationalUnit -Name "Computers" -Path "DC=LabDomain,DC=local"

# Create User Accounts
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@LabDomain.local" -Path "OU=Users,DC=LabDomain,DC=local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Create a Security Group
New-ADGroup -Name "LabAdmins" -GroupScope Global -Path "OU=Users,DC=LabDomain,DC=local"

# Add User to Group
Add-ADGroupMember -Identity "LabAdmins" -Members "jdoe"

Write-Host "Active Directory Lab setup completed successfully."
