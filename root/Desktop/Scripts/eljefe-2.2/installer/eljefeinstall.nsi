; Copyright (C) 2010-2014 Immunity Inc.
; This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
; See the file 'docs/LICENSE' for copying permission.

Name "El Jefe Installer"  

RequestExecutionLevel admin

!include LogicLib.nsh
!include "x64.nsh"
!include "nsProcess.nsh"
!include "nsDialogs.nsh"

SetCompress Off
CRCCheck Off

!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin" ;Require admin rights on NT4+
        messageBox mb_iconstop "Administrator rights required!"
        setErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
        quit
${EndIf}
!macroend
 
Function .onInit
		
	ReadRegStr $R0 HKLM "SOFTWARE\Immunity Inc\El Jefe" "El Jefe" 
	${If} $R0 != ""
		MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
		"El Jefe is already installed. $\n$\nClick `OK` to remove the \
		previous version or `Cancel` to cancel this upgrade." \
		IDOK uninst
		Abort
				
		; Running the uninstaller
		uninst:
			#ClearErrors
			ExecWait '"$INSTDIR\uninstall.exe" _?=$INSTDIR'
			delete $INSTDIR\uninstall.exe
			#Exec $INSTDIR\uninstall.exe
			#ExecWait '"$INSTDIR\uninstall.exe" _?=$INSTDIR'
			#Exec $INSTDIR\uninstall.exe
					
	${EndIf}	
	
	setShellVarContext all
	!insertmacro VerifyUserIsAdmin
FunctionEnd

; Set the installer output file name  
OutFile "ElJefeInstaller.exe"
  
; Set the default installation directory  
InstallDir "C:\Program Files\Immunity Inc\El Jefe" 

; Installation Message
DirText "This will install El Jefe to your computer, as well as automatically start the El Jefe service. Please choose a directory:"

; Config custom pages
Page directory  
Page instfiles 
  
; Specify all files needed for installation  
Section "MainSection" SEC01  
   
	 SetOutPath $SYSDIR
   setoverwrite off
	 File msvcr100.dll

   SetOutPath "$INSTDIR\certs"
   CreateDirectory "$INSTDIR\certs"
   
   ; Put dummy certs
	File template_certs\client.pem
	File template_certs\client.key
	File template_certs\cacert.pem
	File template_certs\server.pem
	
   SetOutPath $INSTDIR
   CreateDirectory $INSTDIR 
   
   File config.ini
	
   ${If} ${RunningX64}
      File ServiceInstall64.exe
      File ElJefeService64.exe  
      WriteRegStr HKLM "SOFTWARE\Immunity Inc\El Jefe" "El Jefe" "$INSTDIR\ElJefeService64.exe"
      SimpleSC::InstallService "El Jefe" "El Jefe" "16" "2" '"$INSTDIR\ServiceInstall64.exe"' "" "" ""
      Pop $0 ; returns an errorcode (<>0) otherwise success (0)

   ${Else}
      File ServiceInstall32.exe
      File ElJefeService32.exe
      WriteRegStr HKLM "SOFTWARE\Immunity Inc\El Jefe" "El Jefe" "$INSTDIR\ElJefeService32.exe"  
      SimpleSC::InstallService "El Jefe" "El Jefe" "16" "2" '"$INSTDIR\ServiceInstall32.exe"' "" "" ""
      Pop $0 ; returns an errorcode (<>0) otherwise success (0)
 
   ${EndIf}	  

   SimpleSC::SetServiceLogon "El Jefe" "SYSTEM" ;ensure we are system user
   Pop $0 
   SimpleSC::StartService "El Jefe" "" 10000
   Pop $0 ; returns an errorcode (<>0) otherwise success (0)

   writeUninstaller "$INSTDIR\uninstall.exe"


SectionEnd 

function un.onInit
	MessageBox MB_OKCANCEL "Permanently remove El Jefe?" IDOK next
		Abort
	next:
!insertmacro VerifyUserIsAdmin
functionEnd

!include WinMessages.nsh
  
section "uninstall"
	SimpleSC::StopService "El Jefe" 1 30
  	Pop $0 ; returns an errorcode (<>0) otherwise success (0)

	; Remove a service
	SimpleSC::RemoveService "El Jefe"
	Pop $0 ; returns an errorcode (<>0) otherwise success (0)

	# Remove files
    ${If} ${RunningX64}
		${nsProcess::KillProcess} "ServiceInstall64.exe" $R0
		${nsProcess::KillProcess} "ElJefeService64.exe" $R1
		; Wait for process to die	
		Sleep 2000 
		delete $INSTDIR\ServiceInstall64.exe
		delete $INSTDIR\ElJefeService64.exe
    ${Else}
        delete $INSTDIR\ElJefeService32.exe
		delete $INSTDIR\ServiceInstall32.exe
    ${EndIf}
	
	delete $INSTDIR\config.ini
	delete $INSTDIR\certs\client.pem
	delete $INSTDIR\certs\client.key
	delete $INSTDIR\certs\cacert.pem
	delete $INSTDIR\certs\server.pem
	
	# Always delete uninstaller as the last action
	delete $INSTDIR\uninstall.exe
 
	# Try to remove the install directory - this will only happen if it is empty
	rmDir $INSTDIR\certs
	rmDir $INSTDIR

	DeleteRegKey HKLM "SOFTWARE\Immunity Inc\El Jefe"
sectionEnd
