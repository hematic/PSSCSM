# PSSCSM
PowerShell Functions for performing SCSM functions on a machine without the SCSM Console

![alt text](https://github.com/hematic/Storage/raw/master/SCSM.jpg)

# Requirements
 - Know the name of a server with the SCSM Commandlets installed.
 - Valid Credentials for both the remote connection for the SCSM Console machine and for the SCSM commandlets.
 - PowerShell 3.0 or greater

# Reason for the module

As far as i could find when i started having to work with SCSM, there was no way to make adjustments to tickets on machines that did not have the console installed. This meant that when trying to automate tasks using Jenkins i would either have to install the console on all of my agents or restrict the tasks to just a few that i installed it on. I didnt really want to do either so i went about writing wrappers for many of the commandlets i used to invoke-command to a remote server with the console and run the actual code inside of that. However i wanted to keep the syntax of the modules so PSSCSM was born.

Their are no added commands here. In fact many of the commandlets that are native have not been ported to this because i haven't needed them. This module simply serves as a example for how to wrap the SCSM commandlets to be able to be used remotely for anyone else who may have a need.

# Features
  - Creation of a new SCSM Incident
  - Closing of a SCSM Incident
  - Retrieving an SCSM Incident
  - Setting the assigned user of an SCSM Incident
  - Creation of a new SCSM Service Request
  - Changing the Status of a SCSM Service Request
  - Retrieval of a SCSM Service Request
    - By ID
    - By Title
  - Adding a comment to a SCSM Service Request
  - Setting a template on a SCSM Service Request
  - Setting the affected user of a SCSM Service Request
  - Setting the assigned support group of a SCSM Service Request
  - Setting the assigned user of a SCSM Service Request
  - Setting the title of a SCSM Service Request

# Examples and Help

Currently located inside the functions themselves.
