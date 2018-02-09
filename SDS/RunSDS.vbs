Function RunSDS()
	dim shell
	set shell=createobject("wscript.shell")
	shell.Popup "Updating Service Desk Scripts",, "Run SDS"
	shell.run "\\dc1wfs01\home\_PSscripts_\sds.bat"
	set shell=nothing
End Function

RunSDS()