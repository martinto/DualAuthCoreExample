# Cookie and JWT (token) authentication in aspnet core 2.0

There are many examples of token authentication available, including [Mark Macneil's](https://github.com/mmacneil) [AngularJS authentication example](https://github.com/mmacneil/AngularASPNETCoreAuthentication) on which the JWT code in this example is based. However, there isn't much on combining the out of the box cookie based authentication with JWT whilst retaining standard cookie authentication behaviours like setting HttpContext.User.

The aspnet core 2 framework will not set `HttpContext.User` if either the default authentication method is set expicitely or it is set in the Authorize attribute. Thankfully the first method added becomes the implicit default so this can be dealt with.

The commit which adds JWT authentication is [5d34a84](https://github.com/martinto/DualAuthCoreExample/commit/5d34a842e58027f5e39540c46d7f89c0f9eca7ea). You will need to customise this to fit in with your application, in particular a role claim (`rol`) with the value `api_access` is automatically added during login, in practise you would almost certainly want to control access to the API and not grant it to all users.

Note that in order to test the token authentication the site has to be running https with a trusted certificate. Use the PowerShell script MakeSelfSignedCertificate to generate a certificate. Once made you will have to export by running certlm.msc:

* Open Personal/Certificates
* Right click on dualauthrcore.org and choose All Tasks/Export
* Export it with the private key and use a password
* Open Trusted Root Certification Authorities/Certificates
* In the Action menu choose All Tasks/Import, when you get to browse for the file choose All Files and look for your exported .pfx file

Now fire up notepad.exe with administrator permissions and open C:\Windows\System32\drivers\etc\hosts, add:

`127.0.0.1 dualcoreauth.org`

Now when the project is run it will be listening on `https://dualauthcore.org:53825` and the certificate will be trusted.

_Please note that adding a Trusted Root Certification Authority introduces a security vulnerability. Anyone who gets hold of the private certificate will be able to stage a man in the middle attack on any site you visit. Only ever do this if you understand the consequences and ensure that the .pfx file and its password are protected._

dotnet core has a method for making secrets available during development in the dotnet user-secrets command. You will need to set two (cd into `DualAuthCoreExample\DualAuthCoreExample` first:

`dotnet user-secrets set Jwt:SecretKey =LeWZj567fojiLNXMxF5Goo6Lhm1J5xQy`

`dotnet user-secrets set DualAuthCoreExample:CertificatePassword "the password you used during export"`

The JWT scret should be a random 32 character string (I used [random.rrg](https://www.random.org/strings/) to generate two 16 character string and joined them).