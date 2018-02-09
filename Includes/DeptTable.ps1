$DeptTable = @{
	"DP&E/DPE BPB Building Professionals Board/00003405" = @{ HomeDir = "\\vfilerdpi\DPI-Home\";Domain = "bpb.nsw.gov.au";				    ADGroups = @("BPB Users",	"DL DP&E BPB All",	"Lync-BPB")};
	"CCRDC" =									@{HomeDir = "\\vfiler01\CCRDC-Home\";			Domain = "ccrdc.nsw.gov.au";				ADGroups = @("CCRDC Users",	"DL CCRDC Staff")};
	"cgsydtl (possibly external)" = 			@{HomeDir = "\\VFILERDPC\DPC-Home\"; 			Domain = "cgsydtl.com"; 					ADGroups = @("DPC Users")};
	"DPC" = 									@{HomeDir = "\\vfilerdpc\dpc-home\"; 			Domain = "dpc.nsw.gov.au"; 					ADGroups = @("DPC Users", "DL DPC Core", "Lync-DPC")};
	"DPC (Governor)" = 							@{HomeDir = "\\vfilerdpc\dpc-home\"; 			Domain = "governor.nsw.gov.au"; 			ADGroups = @("Map Drive G DPC-Group CIFS", "DL DPC Governor", "Lync-OFS")};
	"OFS/Fair Trading" = 						@{HomeDir = "\\vfilerdfs\DFS-FT-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("FT Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/GAO" = 								@{HomeDir = "\\vfilerdfs\DFS-GAO-Home\";	 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-GAO Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Corporate Affairs" = 					@{HomeDir = "\\vfilerdfs\OFS-CA-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS Corporate Affairs Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Corporate Finance" = 					@{HomeDir = "\\vfilerdfs\OFS-CF-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS CF Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Corporate Operating Model" = 			@{HomeDir = "\\vfilerdfs\OFS-COM-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS Corporate Operating Model Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Corporate Services" = 					@{HomeDir = "\\vfilerdfs\OFS-CS-HOME\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-CS Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Execuite Directors Office" = 			@{HomeDir = "\\vfilerdfs\OFS-EDO-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS Executive Directors Office Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/FT CL" = 								@{HomeDir = "\\vfilerdfs\OFS-FT-CL-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-FT-CL Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/FT CS" = 								@{HomeDir = "\\vfilerdfs\OFS-FT-CS-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-FT-CS Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/FT Home Building" = 					@{HomeDir = "\\vfilerdfs\OFS-FT-HBS-HOME\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-FT-HBS Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/FT PS" = 								@{HomeDir = "\\vfilerdfs\OFS-FT-PS-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-FT-PS Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/ICT Strategic Delivery" = 				@{HomeDir = "\\vfilerdfs\OFS-ICTSD-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS ICT Strategic Delivery Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Legal Audit Risk" = 					@{HomeDir = "\\vfilerdfs\OFS-LAR-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS Legal Audit Risk Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/NSW Procurement" = 					@{HomeDir = "\\vfilerdfs\OFS-NSWP-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS NSW Procurement Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/OCE" = 								@{HomeDir = "\\vfilerdfs\OFS-OCE-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-OCE Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/People" =								@{HomeDir = "\\vfilerdfs\OFS-People-Home\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PEOPLE Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/PW FM" = 								@{HomeDir = "\\vfilerdfs\OFS-PW-FM-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS Public Works Facilities Management Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/ PW GAO ENG" = 						@{HomeDir = "\\vfilerdfs\OFS-PW-GAO-ENG-HOME\"; Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-GAO-ENG Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/ PW PM Hunter New England Region" = 	@{HomeDir = "\\vfilerdfs\OFS-PW-PM-HNE-HOME\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-PM-HNE Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/PW PM North Coast Region" = 			@{HomeDir = "\\vfilerdfs\OFS-PW-PM-NCR-HOME\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-PM-NCR Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/PW PM Riverina Western Region" = 		@{HomeDir = "\\vfilerdfs\OFS-PW-PM-RWR-HOME\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-PM-RWR Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/PW PM South Coast Region" = 			@{HomeDir = "\\vfilerdfs\OFS-PW-PM-SCR-Home\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-PM-SCR Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/PW PM Sydney Region" = 				@{HomeDir = "\\vfilerdfs\OFS-PW-PM-SYD-HOME\"; 	Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-PW-PM-SYD Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/ServiceFirst Outsourcing Project" = 	@{HomeDir = "\\vfilerdfs\OFS-SFOP-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS SF Outsourcing Program Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/SIS" = 								@{HomeDir = "\\vfilerdfs\OFS-SIS-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-SIS Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/StateFleet" = 							@{HomeDir = "\\vfilerdfs\OFS-StateFleet-Home\"; Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS StateFleet Users", "DL OFS All Staff", "Lync-OFS")};
	"OFS/Telco Authority" = 					@{HomeDir = "\\vfilerdfs\OFS-TA-Home\"; 		Domain = "finance.nsw.gov.au"; 				ADGroups = @("OFS-TA Users", "DL OFS All Staff", "Lync-OFS")};
	"TSY/Industrial Relations" = 				@{HomeDir = "\\VFILERTSY\TSY-Home\"; 			Domain = "industrialrelations.nsw.gov.au"; 	ADGroups = @("Map Drive G TSY IR GROUP CIFS", "DL NSWIR All Staff", "Lync-IR")};
	"TSY" = 					 				@{HomeDir = "\\vfilertsy\tsy-home\"; 			Domain = "treasury.nsw.gov.au"; 			ADGroups = @("TSY Users", "TRSY_SERVICENOW_USER", "TSY_INTRANET", "DL TSY ALL", "Lync-TSY")};
	"OCG/CCYP" = 								@{HomeDir = "\\vfiler01\OCG-home\"; 			Domain = "kids.nsw.gov.au"; 				ADGroups = @("CCYP Users", "DL CCYP All", "Lync-Kids")};
	"OCG" = 									@{HomeDir = "\\vfiler01\OCG-home\"; 			Domain = "kidsguardian.nsw.gov.au"; 		ADGroups = @("OCG All Users", "DL OCG All", "Lync-Kids")};
	"OFS/PW Manly Hydrolics" = 					@{HomeDir = "\\vfilerdfs\ofs-pw-mhl-home\"; 	Domain = "mhl.nsw.gov.au"; 					ADGroups = @("OFS-PW-MHL Users", "DL OFS All Staff", "Lync-MHL")};
	"DPC/oiicac.nsw.gov.au" = 					@{HomeDir = "\\VFILERDPC\DPC-Home\"; 			Domain = "oiicac.nsw.gov.au"; 				ADGroups = @("DL DPC Inspector PIC")};
	"DPC/Oipic" = 								@{HomeDir = "\\VFILERDPC\DPC-Home\"; 			Domain = "oipic.nsw.gov.au"; 				ADGroups = @("DL DPC Inspector PIC")};
	"OFS/Government Property" = 				@{HomeDir = "\\vfilerdfs\OFS-GPNSW-Home\"; 		Domain = "property.nsw.gov.au"; 			ADGroups = @("OFS-GPNSW Users", "DL OFS All Staff", "Lync-Property")};
	"PSC" = 									@{HomeDir = "\\vfilerpsc\psc-home\"; 			Domain = "psc.nsw.gov.au"; 					ADGroups = @("PSC Users", "DL PSC All", "Lync-PSC")}; #PSC sub to be added
	"OFS/SICorp" = 								@{HomeDir = "\\vfilerdfs\OFS-SICorp-Home\"; 	Domain = "sicorp.nsw.gov.au"; 				ADGroups = @("OFS-SICORP Users", "DL SICORP STAFF", "Lync-SICORP")};
	"OFS/Teachers Housing Authority" =			@{HomeDir = "\\vfilerdfs\OFS-THA-Home\"; 		Domain = "tha.nsw.gov.au"; 					ADGroups = @("OFS-THA Users", "DL THA All", "Lync-THA")};
	"DPC EP Economic Policy" =					@{HomeDir = "\\VFILERDPC\DPC-Home\"; 			Domain = "dpc.nsw.gov.au"; 					ADGroups = @("DPC Users", "Lync-DPC")};
	"Infosys" = 								@{HomeDir = "\\vfilerdfs-sf\dfs-sf-home\"; 		Domain = "govconnect.nsw.gov.au"; 			ADGroups = @("Infosys Users", "Lync-OFS")};
	"Unisys" = 									@{HomeDir = "\\vfilerdfs-sf\dfs-sf-home\"; 		Domain = "servicefirst.nsw.gov.au"; 		ADGroups = @("Unisys Users", "DL DFS SF Mckell IT Clients", "Lync-SF")}
}