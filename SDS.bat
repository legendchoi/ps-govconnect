ECHO OFF
CLS

:UPDATE
rem 
echo CHECK  : Checking Folders...
if exist h:\scripts ( 
	echo CHECK  : Scripts folder already exist
	copy /Y \\dc1wfs01\home\_PSscripts_\*.ps1 H:\scripts
) else (
	mkdir h:\scripts
	echo CHECK  : scripts folder created
	copy /Y \\dc1wfs01\home\_PSscripts_\*.ps1 H:\scripts
)

if exist h:\scripts\includes ( 
	echo CHECK  : Scripts\includes folder already exist
	copy /Y \\dc1wfs01\home\_PSscripts_\includes\*.ps1 H:\scripts\includes
) else (
	mkdir h:\scripts\includes
	echo CHECK  : scripts\includes folder created
	copy /Y \\dc1wfs01\home\_PSscripts_\includes\*.ps1 H:\scripts\includes
)

if exist h:\scripts\files ( 
	echo CHECK  : Scripts\files folder already exist
	copy /Y \\dc1wfs01\home\_PSscripts_\Files\*.* H:\scripts\files
) else (
	mkdir h:\scripts\files
	echo CHECK  : scripts\files folder created
	copy /Y \\dc1wfs01\home\_PSscripts_\Files\*.* H:\scripts\files
)

echo.
rem echo Update completed. Press any keys to main menu
rem pause


:ROLE
CLS
ECHO.   
ECHO		PLEASE SELECT YOUR ROLE		     
ECHO.
ECHO.
ECHO		1  Tier 1 Agent
ECHO		2  Tier 2 Agent
ECHO.
ECHO.
SET /P R=Type the number then press ENTER: 
ECHO.
IF %R% ==1 GOTO BEGIN1 
IF %R% ==2 GOTO BEGIN2
GOTO END


:BEGIN1
CLS
ECHO.                 
ECHO GovConnectNSW Service Desk Scripts v0.6
ECHO.
ECHO PLEASE MAKE A CHOICE		     
ECHO.
ECHO.
ECHO		(1).  Check User Account Lock Status and Password reset (AD only)
ECHO.
ECHO		(8).  Check Mobile Device Access (AIRCARD AND MOBILEIRON)
ECHO.
ECHO		(10). Check User Info
ECHO.
ECHO		(0).  EXIT
ECHO.
ECHO.
SET /P M=Type the number then press ENTER: 
ECHO.
IF %M% ==0  GOTO GETOUT 
IF %M% ==10 GOTO CHKMNG
IF %M% ==9  GOTO DL
IF %M% ==8  GOTO MDM
IF %M% ==7  GOTO SHAREDMAIL
If %M% ==6  GOTO CTX_ACCESS
if %M% ==5  goto NET_ACC
If %M% ==4  GOTO COPY_GROUP
If %M% ==3  GOTO ACC_TERM
If %M% ==2  GOTO ACC_CREATION
If %M% ==1  GOTO PW_RST
GOTO END

:BEGIN2
CLS
ECHO.                 
ECHO GovConnectNSW Service Desk Scripts v0.6
ECHO.
ECHO        PLEASE MAKE A CHOICE
ECHO.
ECHO.
ECHO		(1).   Account Status
echo.
ECHO		(2).   Account Creation
echo.
ECHO		(3).   Account Terminator
echo.
ECHO		(4).   Network Access Privilege Change (Same As Account)
echo.
echo		(5).   Network Access Privilege Change (Shared Folder - BETA)
echo.
ECHO		(6).   CITRIX Acess
echo.
ECHO		(7).   MailBox Access
echo.
ECHO		(8).   MDM Access
echo.
ECHO		(9).   DL Access
echo.
ECHO		(10).  User Info
echo.
echo		(11).  Mapping Drive
echo.
echo		(12).  Shared Mailbox - User List
echo.
ECHO		(0).   EXIT
ECHO.
ECHO.
SET /P M=Type the number then press ENTER: 
ECHO.
IF %M% ==0  GOTO GETOUT
IF %M% ==12 GOTO SMUL
IF %M% ==11 GOTO MMAP
IF %M% ==10 GOTO CHKMNG
IF %M% ==9  GOTO DL
IF %M% ==8  GOTO MDM
IF %M% ==7  GOTO SHAREDMAIL
If %M% ==6  GOTO CTX_ACCESS
if %M% ==5  goto NET_ACC
If %M% ==4  GOTO COPY_GROUP
If %M% ==3  GOTO ACC_TERM
If %M% ==2  GOTO ACC_CREATION
If %M% ==1  GOTO PW_RST
GOTO END

:GETOUT
rem EXIT
GOTO QUIT

:SMUL
powershell.exe -File H:\Scripts\list-sharedMail-Users.ps1
GOTO END

:MMAP
powershell.exe -File H:\Scripts\Manual-Mapping.ps1
GOTO END

:NET_ACC
powershell.exe -File H:\Scripts\Get-FolderAccess.ps1
GOTO END

:DL
powershell.exe -File H:\Scripts\Distribution-List.ps1
GOTO END

:PW_RST
powershell.exe -File H:\Scripts\Password-Reset.ps1
GOTO END

:CHKMNG
powershell.exe -File H:\Scripts\Get-ADManager.ps1
GOTO END

:MDM
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\Check-DeviceRegistration.ps1
GOTO END

:SHAREDMAIL
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\SharedEmail.ps1
GOTO END

:COPY_GROUP
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\Copy-ADUserGroup2.3.ps1
GOTO END

:ACC_CREATION
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\Account-Creation.ps1
GOTO END

:ACC_TERM
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\Terminator.ps1
GOTO END

:CTX_ACCESS
powershell.exe -ExecutionPolicy Bypass -File H:\Scripts\Citrix-Access.ps1
GOTO END

:END
ECHO Completed. Bringing up main menu again...
pause
IF %R% ==1 GOTO BEGIN1 
IF %R% ==2 GOTO BEGIN2

%~f0 rem call %~dp0go.bat

:QUIT
h: