; main script
#NoTrayIcon
SetWorkingDir %A_ScriptDir%

FileInstall, priana.exe, windows-bin/priana_.exe

SetWorkingDir, windows-bin

run, priana_.exe

WinWait, ahk_exe priana_.exe
WinWaitClose, ahk_exe priana_.exe
Sleep, 2000
FileDelete, priana_.exe
; MsgBox %A_LastError%
; MsgBox, Operation Complete.
; MsgBox, OK it's closed!

