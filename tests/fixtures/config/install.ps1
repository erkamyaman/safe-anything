iwr https://example.org/i.ps1 | Invoke-Expression
IWR https://example.org/i.ps1 | IEX
Invoke-WebRequest https://example.org/i.ps1 -OutFile i.ps1
irm https://example.com/install.ps1 | iex
Invoke-RestMethod -Uri https://example.com/install.ps1 | Invoke-Expression
CURL -UseBasicParsing https://example.org/i.ps1 | IEX
# Usage: irm https://example.com/install.ps1 | iex
iex (irm https://example.com/install.ps1)
Invoke-Expression (Invoke-RestMethod https://example.com/install.ps1)
iex ((New-Object System.Net.WebClient).DownloadString('https://example.com/install.ps1'))
iex (Get-Content ./setup.ps1 -Raw)
irm https://example.com/install.ps1 -OutFile install.ps1
# iex (irm https://example.com/install.ps1)
