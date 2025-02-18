## About Duende.IdentityModel.OidcClient

This directory contains several libraries for building OpenID Connect (OIDC) native
clients. The core `Duende.IdentityModel.OidcClient` library is a certified OIDC relying party and
implements [RFC 8252](https://tools.ietf.org/html/rfc8252/), "OAuth 2.0 for native
Applications". The `Duende.IdentityModel.OidcClient.Extensions` provides support for
[DPoP](https://datatracker.ietf.org/doc/html/rfc9449) 
extensions to Duende.IdentityModel.OidcClient for sender-constraining tokens.

## Samples
OidcClient targets .NET Standard, making it suitable for .NET and .NET
Framework. It can be used to build OIDC native clients with a variety of .NET UI tools.
The [samples](https://github.com/DuendeSoftware/foss/tree/main/identity-model-oidc-client/samples)
shows how to use it in 
- .NET MAUI
- WPF with the system browser
- WPF with an embedded browser
- WinForms with an embedded browser
- Cross Platform Console Applications (relies on kestrel for processing the callback)
- Windows Console Applications (relies on an HttpListener - a wrapper around the windows HTTP.sys driver)
- Windows Console Applications using custom uri schemes

## Documentation 

More documentation is available
[here](https://docs.duendesoftware.com/foss/identitymodel.oidcclient/).


## Certification
OidcClient is a [certified](http://openid.net/certification/) OpenID Connect
relying party implementation.

## Feedback

Duende.IdentityModel.OidcClient is released as open source under the 
[Apache 2.0 license](https://github.com/DuendeSoftware/foss/blob/main/LICENSE). 
Bug reports and contributions are welcome at 
[the GitHub repository](https://github.com/DuendeSoftware/foss).
