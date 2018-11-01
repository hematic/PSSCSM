Function New-Incident {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the title of your ticket.')]
        [ValidateLength(1,255)]
        [String]$Title,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the description of your ticket.')]
        [String]$Description,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the Impact of your ticket.')]
        [Validateset("Low","Medium","High")]
        [String]$Impact,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the urgency of your ticket.')]
        [Validateset("Low","Medium","High")]
        [String]$Urgency,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the Classification of your ticket.')]
        [String]$Classification,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the affectedUser of your ticket.')]
        [String]$AffectedUser,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the SupportGroup of your ticket.')]
        [String]$SupportGroup,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the Source of your ticket.')]
        [Validateset('Portal', 'Console', 'Security Tools',  'Sparkbar', 'Walk-in', 'Intel Report', 'Phone', 'IM', 'SIEM', "Configuration Manager", 'Operations Manager', 'Non-user Query', 'Spark Bar', 'System', 'Email')]
        [String]$Source,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )
    Try{
        Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $Splat = @{
                'Title' = $Using:Title
                'Description' = $Using:Description
                'Impact' = $Using:Impact
                'Urgency' = $Using:Urgency
                'Classification' = $Using:Classification
                'SupportGroup' = $Using:SupportGroup
                'AffectedUser' = $Using:AffectedUser
                'Source' = $Using:Source
                'Credential' = $Using:Credential
            }
            New-SCSMIncident @Splat
        }
    }
    Catch{
        Write-Error $_
    }
}
Function Close-Incident {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is ticket ID to close including the "IR".')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='You must supply a comment when closing the ticket via this function.')]
        [String]$Comment,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='The status to set the ticket to.')]
        [Validateset("Closed-Confirmed","Resolved")]
        [String]$Status,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $Splat = @{
                'ID' = $Using:ID
                'Comment' = $Using:Comment
                'Status' = $Using:Status
                'Credential' = $Using:Credential
            }
            Set-SCSMIncident @Splat
        }
    }
    Catch{
        Write-Error $_
    }
}
Function Get-WCIncident {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is ticket ID to find including the "IR".')]
        [String]$ID,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is title to find.')]
        [String]$Title,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    If($ID){
        Try{
            Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
                $Splat = @{
                    'ID' = $Using:ID
                    'Credential' = $Using:Credential
                }
                Get-SCSMIncident @Splat
            }
        }
        Catch{
            Write-Error $_
        }
    }
    ElseIf($Title){
        Try{
            Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
                $Splat = @{
                    'Title' = $Using:Title
                    'Credential' = $Using:Credential
                }
                Get-SCSMIncident @Splat
            }
        }
        Catch{
            Write-Error $_
        }  
    }
}
Function Set-WCIncidentAssignedUser {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the ID of your ticket.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the user to assign.')]
        [String]$Username,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )
    Try{
        Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $IncidentClass = Get-SCSMClass -name System.WorkItem.Incident$ -Credential $Using:Credential
            $UserClass = Get-SCSMClass -name System.Domain.User$ -Credential $Using:Credential
            $AssignedToUserRelClass  = Get-SCSMRelationshipClass -Name System.WorkItemAssignedToUser$ -Credential $Using:Credential
            $Incident = Get-SCSMObject -Class $IncidentClass -Filter "ID -eq $Using:ID" -Credential $Using:Credential
            $User = Get-SCSMObject -Class $UserClass -Filter "Username -eq $Using:Username"  -Credential $Using:Credential
            New-SCSMRelationshipObject -RelationShip $AssignedToUserRelClass -Source $Incident -Target $User -Bulk -Credential $Using:Credential
        }
    }
    Catch{
        Write-Error $_
    }
}
Function New-WCServiceRequest {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='EX: ServiceRequestAreaEnum.Directory.AccountManagement or ServiceRequestAreaEnum.Messaging.Server')]
        [ValidateSet('Directory.AccountManagement','Software.Other','Messaging.Other','Facilities.Power','Software.OperatingSystem','Facilities.Other',
        'Security.Other','Messaging.Client','Content.Extranet','Software.Patch','Software.Configuration','Hardware.Other','Directory.OUManagement',
        'File','File.DiskVolumesAndDFS','ServiceRequestAreaEnum','Messaging','Infrastructure.NetworkConnectivity','Software.Installation',
        'Security','Operations','Other','Facilities','Infrastructure.Backups','Content','Operations.Other','Directory.Other','Software',
        'File.Shares','File.Other','Software.Application','Hardware.Server','Operations.Process','Security.AccessControl','Infrastructure.ProxyOrFirewall',
        'Infrastructure.Monitoring','Operations.Management','Hardware.Components','Security.AccountManagement','Content.Intranet','Infrastructure.RemoteAccess',
        'Security.Information','Operations.Documentation','Software.Licenses','Directory','Infrastructure.Telephony','Hardware.Network','Software.Driver',
        'Hardware','File.RestoreFile','Hardware.Storage','Content.Other','Infrastructure.NameResolution','Infrastructure.Other','Messaging.Server',
        'Hardware.Client','Infrastructure.ServerServices','Content.Knowledge','Software.Firmware','Security.Physical','Infrastructure')]
        [String]$ServiceRequestArea,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='The enum value of the service request area.')]
        [string]$ServiceRequestEnum,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='The Priority of the new request.')]
        [ValidateSet("ServiceRequestPriorityEnum.Low","ServiceRequestPriorityEnum.Medium","ServiceRequestPriorityEnum.High","ServiceRequestPriorityEnum.Immediate")]
        [String]$Priority,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='The Urgency of the new request.')]
        [ValidateSet("ServiceRequestUrgencyEnum.Low","ServiceRequestUrgencyEnum.Medium","ServiceRequestUrgencyEnum.High","ServiceRequesturgencyEnum.Immediate")]
        [String]$Urgency,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the title of your request.')]
        [ValidateLength(1,255)]
        [String]$Title,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the description of your request.')]
        [String]$Description,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the source of your request.')]
        [ValidateSet('SparkBar','EMail','IM','Portal','Phone','Other','Walk-in','Non-User Query','Spark Bar','Intel Report')]
        [String]$Source,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            Try{
                #Get the Service Request Enumeration for the Area Using either the name or the enum value.
                If($Using:ServiceRequestEnum){
                    $SRArea = Get-SCSMEnumeration -Name $Using:ServiceRequestEnum -ErrorAction Stop
                }
                Else{
                    $SRArea = Get-SCSMEnumeration -Name $('ServiceRequestAreaEnum.' + $Using:ServiceRequestArea) -ErrorAction Stop
                }
                #Get the Service Request Class.
                $SRClass = Get-SCSMClass -Name System.WorkItem.ServiceRequest$ -ErrorAction Stop
                #Get the Service Request Enumeration for the Priority
                $SRPriority = Get-SCSMEnumeration -Name $Using:Priority -ErrorAction Stop
                #Get the Service Request Enumeration for the Urgency
                $SRUrgency = Get-SCSMEnumeration -Name $Using:Urgency -ErrorAction Stop
                #Create the ticket.
                $SRHashTable = @{
                    Title = $using:Title;
                    Description = $Using:Description
                    Urgency = $SRUrgency
                    Priority = $SRPriority
                    ID = “SR{0}”
                    Area = $SRArea
                    Source = $Using:Source
                }
                $Ticket = New-SCSMOBject -Class $SRClass -PropertyHashtable $SRHashTable -ErrorAction Stop -Passthru
                Write-Output $Ticket
            }
            Catch{
                Write-error $_.exception.message
            }
        }
        Write-Output $SR
    }
    Catch{
        Write-Error $_.exception.message
    }
}
Function Set-WCServiceRequestStatus {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the request ID to close including the "SR".')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the status to set the service request to.')]
        [ValidateSet("New", "Closed", "Completed", "Failed", "Cancelled", "On Hold", "In Progress", "Submitted")]
        [String]$Status,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    ) 

    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            Try{
                $ServiceRequestClass = Get-SCSMClass -Name System.WorkItem.ServiceRequest$ -ErrorAction Stop
                $ServiceRequestObj = Get-SCSMObject -Class $ServiceRequestClass -Filter "ID = $Using:ID" -ErrorAction Stop
                Set-SCSMObject -SMObject $ServiceRequestObj -Property Status -Value $Using:Status -ErrorAction Stop
            }
            Catch{
                Write-Error $_
            }
        }
        Write-Output $SR
    }
    Catch{
        Write-Error $_
    }
}
Function Get-WCServiceRequestByID {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the request ID to retrieve including the "SR".')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )
    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            Try{
                $ServiceRequestClass = Get-SCSMClass -Name System.WorkItem.ServiceRequest$
                Get-SCSMObject -Class $ServiceRequestClass -Filter "Name = $Using:ID" -ErrorAction Stop
            }
            Catch{
                Write-Error $_
            }
        }
        Write-Output $SR
    }
    Catch{
        Write-Error $_
    }

}
Function Get-WCServiceRequestByTitle {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the title of the request to retrieve.')]
        [String]$Title,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $ServiceRequestClass = Get-SCSMClass -Name System.WorkItem.ServiceRequest$
            Get-SCSMObject -Class $ServiceRequestClass -Filter "Title = $Using:Title" -ErrorAction Stop
        }
        Write-Output $SR
    }
    Catch{
        Write-Error $_
    }

}
Function Add-WCServiceRequestComment {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the request ID to close including the "SR".')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the Display name for the comment.')]
        [String]$EnteredBy,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the comment.')]
        [String]$Comment,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This credential must have rights to SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    ) 

    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $ServiceRequestClass = Get-SCSMClass -Name System.WorkItem.ServiceRequest$
            $ServiceRequestObj = Get-SCSMObject -Class $ServiceRequestClass -Filter "ID = $Using:ID" -ErrorAction Stop
            $NewGUID = ([guid]::NewGuid()).ToString()
            $Projection = @{__CLASS = "System.WorkItem.ServiceRequest";
                            __SEED = $ServiceRequestObj;
                            AnalystCommentLog = @{__CLASS = "System.WorkItem.TroubleTicket.AnalystCommentLog";
                                                __OBJECT = @{Id = $NewGUID;
                                                                DisplayName = $NewGUID;
                                                                Comment = $Using:Comment;
                                                                EnteredBy  = $Using:EnteredBy;
                                                                EnteredDate = (Get-Date).ToUniversalTime();
                                                                IsPrivate = $false
                                                            }
                                                }
                            }
            $Projection | Convertto-json | out-file c:\temp\projection.txt
            New-SCSMObjectProjection -Type "System.WorkItem.ServiceRequestProjection" -Projection $Projection -ErrorAction Stop
        }
        Write-Output $SR
    }
    Catch{
        Write-Error $_
    }
}
Function Set-WCServiceRequestTemplate {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the service request ID.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the name of the template to set.')]
        [String]$Template,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is credential for SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $SR = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            Try{
                #Get Projection Created Service Request
                $SRTypeProjection = Get-SCSMTypeProjection -name System.WorkItem.ServiceRequestProjection$ -ErrorAction Stop
                $SRProjection = Get-SCSMObjectProjection -ProjectionName $srTypeProjection.Name -filter "id -eq $Using:ID" -ErrorAction Stop

                #Set the template
                $SRTemplate = Get-SCSMObjectTemplate -DisplayName $Using:template -ErrorAction Stop
                $Result = Set-SCSMObjectTemplate -Projection $SRProjection -Template $SRTemplate -ErrorAction Stop
                Write-Output $Result
            }
            Catch{
                Write-error $_.exception.message
            }
        }
        Write-Output $SR
    }
    Catch{
        Write-error $_.exception.message
    }
}
Function Set-WCServiceRequestAffectedUser {
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is samaccountname of the affected user.')]
        [String]$SamAccountName,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the service request ID.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the credential ofr SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $Result = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            Try{
                $UserClass = Get-SCSMClass -name System.Domain.User$ -ErrorAction Stop
                $AffectedUserRelClass  = Get-SCSMRelationshipClass -Name System.WorkItemAffectedUser$ -ErrorAction Stop
                $SRClass = Get-SCSMClass -name System.WorkItem.ServiceRequest$ -ErrorAction Stop
                $SRObject = Get-SCSMObject -Class $SRClass -Filter "ID = $($Using:ID)" -ErrorAction Stop
                $SRUser = Get-SCSMObject -Class $UserClass -Filter "Username -eq $($Using:SamAccountName)" -ErrorAction Stop
                New-SCSMRelationshipObject -RelationShip $AffectedUserRelClass -Source $SRObject -Target $SRUser -Bulk -ErrorAction Stop
            }
            Catch{
                Write-error $_.exception.message
            }

        }
        Write-output $Result
    }
    Catch{
        Write-error $_.exception.message
    }
}
Function Set-TestWCServiceRequestAssignedToUser{
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is samaccountname of the assigned user.')]
        [String]$SamAccountName,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the service request ID.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the credential ofr SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $Result = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $AssignedToRelClass =Get-SCSMRelationshipClass -name System.WorkItemAssignedToUser$ -Credential $Using:Credential -ErrorAction Stop
            $UserClass = Get-SCSMClass -name System.Domain.User$ -Credential $Using:Credential
            $SRClass = Get-SCSMClass -name System.WorkItem.ServiceRequest$ -Credential $Using:Credential -ErrorAction Stop
            $SRObject = Get-SCSMObject -Class $SRClass -Filter "ID = $Using:ID" -Credential $Using:Credential -ErrorAction Stop
            $User = Get-SCSMObject -Class $UserClass -Filter "Username -eq $Using:SamAccountName" -Credential $Using:Credential
            New-SCSMRelationshipObject -RelationShip $AssignedToRelClass -Source $SRObject -Target $User -Credential $Using:Credential -Bulk
        }
        Write-output $Result
    }
    Catch{
        Write-Output $_.exception.message
    }
}
Function Set-WCServiceRequestAssignedSupportGroup{
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is support group enumeration string.')]
        [String]$SupportGroup,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the service request ID.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the credential for SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $Result = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $AssignedGroup = Get-SCSMEnumeration -Credential $Using:Credential -ErrorAction Stop | Where-Object {$_.displayname -eq $Using:SupportGroup -and $_.identifier -like '*ServiceRequest*'}
            $SRClass = Get-SCSMClass -name System.WorkItem.ServiceRequest$ -Credential $Using:Credential -ErrorAction Stop
            $SRObject = Get-SCSMObject -Class $SRClass -Filter "ID = $Using:ID" -Credential $Using:Credential -ErrorAction Stop
            $SRObject | Set-SCSMObject -Property SupportGroup -Value $AssignedGroup -Credential $Using:Credential -ErrorAction Stop
        }
        Write-output $Result
    }
    Catch{
        Write-Output $_.exception.message
    }
}
Function Set-WCServiceRequestTitle{
    [CmdletBinding(SupportsShouldProcess=$False,ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is title of the ticket.')]
        [String]$Title,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the service request ID.')]
        [String]$ID,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the credential for SCSM.')]
        [pscredential]$Credential,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,ValueFromPipelineByPropertyName = $False, HelpMessage='This is the server name of the machine with the SCSM commandlets installed.')]
        [String]$SCSMServer
    )

    Try{
        $Result = Invoke-Command -ComputerName $SCSMServer -Credential $Credential -ScriptBlock {
            $SRClass = Get-SCSMClass -name System.WorkItem.ServiceRequest$ -Credential $Using:Credential -ErrorAction Stop
            $SRObject = Get-SCSMObject -Class $SRClass -Filter "ID = $Using:ID" -Credential $Using:Credential -ErrorAction Stop
            $SRObject | Set-SCSMObject -Property Title -Value $Using:Title -Credential $Using:Credential -ErrorAction Stop
        }
        Write-output $Result
    }
    Catch{
        Write-Output $_.exception.message
    }
}
