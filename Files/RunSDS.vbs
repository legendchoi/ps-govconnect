Function RunSDS()
	dim shell
	set shell=createobject("wscript.shell")
	'shell.Popup "Updating Service Desk Scripts",, "Run SDS"
	update = MsgBox ("Updating Service Desk Scripts?",vbYesNoCancel, "Service Desk Script")
	Select Case update
		Case vbYes
			shell.run "\\dc1wfs01\home\_PSscripts_\sds.bat Yes"
		Case vbNo
			shell.run "\\dc1wfs01\home\_PSscripts_\sds.bat No"
	End Select
	set shell=nothing
End Function

RunSDS()