$Forever = Get-Date -Year 2099                                                                                   
New-SelfSignedCertificate -DnsName "dualauthcore.org" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter $Forever
