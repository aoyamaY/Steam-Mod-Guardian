// Heuristic indicators, not verified malware signatures.
rule Guardian_Network_Dynamic_Load_Indicators {
 strings:
  $net1 = "DownloadData" ascii
  $net2 = "GetByteArrayAsync" ascii
  $net3 = "DownloadFile" ascii
  $load1 = "LoadFrom" ascii fullword
  $load2 = "AssemblyLoadContext" ascii
 condition:
  uint16(0) == 0x5a4d and any of ($net*) and any of ($load*)
}
rule Guardian_Network_Process_Indicators {
 strings:
  $net1 = "DownloadFile" ascii
  $net2 = "DownloadData" ascii
  $proc = "ProcessStartInfo" ascii
 condition:
  uint16(0) == 0x5a4d and any of ($net*) and $proc
}

// Additional local heuristic indicators; do not treat individual matches as a confirmed infection.
rule Guardian_Direct_File_Download {
 strings:
  $a = "DownloadFile" ascii wide
  $b = "DownloadHandlerFile" ascii wide
  $c = "URLDownloadToFile" ascii wide
 condition:
  uint16(0) == 0x5a4d and any of them
}
rule Guardian_Managed_Credential_Indicators {
 strings:
  $a = "Login Data" ascii wide
  $b = "Local State" ascii wide
  $c = "ProtectedData" ascii wide
  $d = "Unprotect" ascii wide
 condition:
  uint16(0) == 0x5a4d and any of ($a,$b) and all of ($c,$d)
}
rule Guardian_Native_CrossProcess_Indicators {
 strings:
  $a = "WriteProcessMemory" ascii
  $b = "CreateRemoteThread" ascii
  $c = "VirtualAllocEx" ascii
 condition:
  uint16(0) == 0x5a4d and 2 of them
}
rule Guardian_Steam_Client_Modification_Indicators {
 strings:
  $a = "steamclient.dll" ascii wide nocase
  $b = "steamui.dll" ascii wide nocase
  $c = "WriteAllBytes" ascii wide
  $d = "WriteFile" ascii wide
 condition:
  uint16(0) == 0x5a4d and any of ($a,$b) and any of ($c,$d)
}
