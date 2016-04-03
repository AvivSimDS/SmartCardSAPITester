echo on
rem UNREGISTER SERVERS
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm ARSmartCardSAPConnect.dll /unregister /silent
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm ARSmartCardSAPConnect64.dll /unregister /silent
rem REGISTER SERVERS
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm ARSmartCardSAPConnect.dll /tlb /codebase
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm ARSmartCardSAPConnect64.dll /tlb /codebase
