; Signalith Windows installer. Build on Linux or Windows with NSIS 3:
;   makensis -WX -DVERSION=0.4.0 -DEXE=path/to/signalith.exe deploy/windows/installer/signalith.nsi
; Silent install (for automation):
;   signalith-setup.exe /S /ADMINPASSWORD=... [/OPENSEARCHZIP=C:\path\opensearch.zip] [/OPENSEARCHURL=http://host:9200]
Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef EXE
  !define EXE "signalith.exe"
!endif
!ifndef OUTFILE
  !define OUTFILE "signalith-setup.exe"
!endif

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Signalith"

Name "Signalith ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Signalith"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
BrandingText "Signalith ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Signalith"
VIAddVersionKey "FileDescription" "Signalith SIEM installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Apache License 2.0"

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

Var Password
Var Password2
Var PwBox
Var PwBox2
Var Upgrade
Var OsZip
Var OsUrl

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "This installs Signalith, an open-source SIEM, as a Windows service together with OpenSearch, the database it stores events in.$\r$\n$\r$\nOpenSearch (about 1 GB) is downloaded during setup, so this computer needs internet access. Setup takes a few minutes.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "../../../LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
Page custom PasswordPage PasswordPageLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "Signalith is running.$\r$\n$\r$\nOpen it at http://localhost:8080 and sign in as admin with the password you chose. Then open Add data to start collecting logs from your Windows and Linux computers."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open Signalith now"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenSignalith
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "Signalith needs 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all ; $APPDATA is ProgramData, $SMPROGRAMS is all users
  ; A config from an earlier install means this is an upgrade or repair:
  ; keep the existing password and settings.
  StrCpy $Upgrade "0"
  IfFileExists "$APPDATA\Signalith\signalith.yaml" 0 +2
    StrCpy $Upgrade "1"
  ${GetParameters} $R0
  ${GetOptions} $R0 "/ADMINPASSWORD=" $Password
  ${GetOptions} $R0 "/OPENSEARCHZIP=" $OsZip
  ${GetOptions} $R0 "/OPENSEARCHURL=" $OsUrl
FunctionEnd

Function PasswordPage
  ${If} $Upgrade == "1"
    Abort ; skip: the existing admin password stays
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "Admin password" "Choose the password for the admin account."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 24u "You sign in to Signalith as admin with this password. Use at least 8 characters. You can change it later with: signalith passwd"
  Pop $0
  ${NSD_CreateLabel} 0 32u 100% 10u "Password"
  Pop $0
  ${NSD_CreatePassword} 0 44u 60% 12u "$Password"
  Pop $PwBox
  ${NSD_CreateLabel} 0 64u 100% 10u "Confirm password"
  Pop $0
  ${NSD_CreatePassword} 0 76u 60% 12u "$Password"
  Pop $PwBox2
  ${NSD_SetFocus} $PwBox
  nsDialogs::Show
FunctionEnd

Function PasswordPageLeave
  ${NSD_GetText} $PwBox $Password
  ${NSD_GetText} $PwBox2 $Password2
  StrLen $0 $Password
  ${If} $0 < 8
    MessageBox MB_ICONEXCLAMATION "The password must be at least 8 characters."
    Abort
  ${EndIf}
  ${If} $Password != $Password2
    MessageBox MB_ICONEXCLAMATION "The passwords do not match."
    Abort
  ${EndIf}
FunctionEnd

Function OpenSignalith
  ExecShell "open" "http://localhost:8080"
FunctionEnd

Section "Signalith" SecMain
  SectionIn RO
  SetRegView 64
  SetOutPath "$INSTDIR"
  ; Stop a running Signalith so its program file can be replaced.
  DetailPrint "Stopping Signalith if it is running"
  nsExec::Exec 'powershell -NoProfile -Command "Stop-Service -Name Signalith -Force -ErrorAction SilentlyContinue"'
  Pop $0

  File "/oname=signalith.exe" "${EXE}"
  File "setup.ps1"
  File "/oname=LICENSE.txt" "../../../LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; The password reaches setup.ps1 through the environment, never a command line.
  ${If} $Upgrade == "0"
  ${AndIf} $Password != ""
    System::Call 'Kernel32::SetEnvironmentVariable(t "SIGNALITH_ADMIN_PASSWORD", t "$Password")'
  ${EndIf}
  StrCpy $1 ""
  ${If} $OsZip != ""
    StrCpy $1 '$1 -OpenSearchZip "$OsZip"'
  ${EndIf}
  ${If} $OsUrl != ""
    StrCpy $1 '$1 -OpenSearchUrl "$OsUrl"'
  ${EndIf}
  DetailPrint "Setting up OpenSearch and Signalith (this takes a few minutes)"
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\setup.ps1" -InstallDir "$INSTDIR"$1'
  Pop $0
  System::Call 'Kernel32::SetEnvironmentVariable(t "SIGNALITH_ADMIN_PASSWORD", p 0)'
  ${If} $0 != "0"
    DetailPrint "Setup failed (exit code $0). The messages above say why."
    MessageBox MB_ICONSTOP "Signalith setup did not finish. The messages in the details list say what went wrong. Fix it and run this installer again to retry; nothing is lost." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}

  WriteINIStr "$SMPROGRAMS\Signalith.url" "InternetShortcut" "URL" "http://localhost:8080"

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "Signalith"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "The Signalith authors"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\signalith.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "https://github.com/jrsamsanchez/Signalith"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\setup.ps1" -InstallDir "$INSTDIR" -Uninstall'
  Pop $0
  Delete "$SMPROGRAMS\Signalith.url"
  RMDir /r "$INSTDIR\opensearch"
  Delete "$INSTDIR\signalith.exe"
  Delete "$INSTDIR\setup.ps1"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DetailPrint "Your events and settings are kept in $APPDATA\Signalith. Delete that folder to remove them."
SectionEnd
