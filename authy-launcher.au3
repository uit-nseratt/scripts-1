; Authy Launcher
; Version 1.0
; Switch between personal or work Authy profile.
; nseratt@gmail.com

#include <GUIConstantsEx.au3>
#include <FileConstants.au3>

ProcessClose("Authy Desktop.exe")


 
 
$authyapp = @LocalAppDataDir & "\authy-electron\Authy Desktop.exe"
$authydir = @AppDataDir & "\Authy Desktop"
$authyworkdir = @AppDataDir & "\Authy.Work"
$authypersonaldir = @AppDataDir & "\Authy.Personal"

If NOT FileExists($authyapp) Then
	MsgBox($MB_SYSTEMMODAL, "Authy Launcher", "Authy does not appear to be installed. Exiting.", 20)
	Exit
EndIf

If NOT FileExists($authyworkdir) Then
 DirCreate($authyworkdir)
EndIf

If NOT FileExists($authypersonaldir) Then
     DirCreate($authypersonaldir)
EndIf

If NOT FileExists($authyworkdir  & "\Cookies") Then
	If FileExists($authydir & "\Cookies") Then
			DirCopy($authydir, $authyworkdir, $FC_OVERWRITE)
	EndIf
EndIf


Local $hGUI = GUICreate("Authy Launcher", 290, 100)
GUICtrlCreateLabel("Which Authy profile would you like to launch?", 15, 10)
Local $idButton_Personal = GUICtrlCreateButton("Personal", 20, 50, 120, 40)
Local $idButton_Work = GUICtrlCreateButton("Work", 150, 50, 120, 40)
GUISetIcon($authyapp, 0, $hGUI)  
GUISetState(@SW_SHOW, $hGUI)


    ; Loop until the user exits.
    While 1
        Switch GUIGetMsg()
            Case $GUI_EVENT_CLOSE
                ExitLoop

            Case $idButton_work
            	ProcessClose("Authy Desktop.exe")
				DirRemove($authydir,1)
			    Run(@comspec & ' /C " mklink /J "' & $authydir & '" "' & $authyworkdir & '""',  "", @SW_HIDE)
 
			    sleep(1500)
				Local $iPID = Run($authyapp)

				ExitLoop
            Case $idButton_personal 
            	ProcessClose("Authy Desktop.exe")
 				DirRemove($authydir,1)
				Run(@comspec & ' /C " mklink /J "' & $authydir & '" "' & $authypersonaldir & '"" ', "", @SW_HIDE)
 			    sleep(1500)

				Local $iPID = Run($authyapp)

				ExitLoop
        EndSwitch
    WEnd
 
    GUIDelete($hGUI)