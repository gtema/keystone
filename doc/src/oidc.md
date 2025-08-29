# Authentication using the Authorization Code flow and Keystone serving as RP

```mermaid
sequenceDiagram

    Actor Human
    Human ->> Cli: Initiate auth
    Cli ->> Keystone: Fetch the OP auth url
    Keystone --> Keystone: Initialize authorization request
    Keystone ->> Cli: Returns authURL of the IdP with cli as redirect_uri
    Cli ->> User-Agent: Go to authURL
    User-Agent -->> IdP: opens authURL
    IdP -->> User-Agent: Ask for consent
    Human -->> User-Agent: give consent
    User-Agent -->> IdP: Proceed
    IdP ->> Cli: callback with Authorization code
    Cli ->> Keystone: Exchange Authorization code for Keystone token
    Keystone ->> IdP: Exchange Authorization code for Access token
    IdP ->> Keystone: Return Access token
    Keystone ->> Cli: return Keystone token
    Cli ->> Human: Authorized

```

## TLDR

The user client (cli) sends authentication request to Keystone specifying the
identity provider, the preferred attribute mapping and optionally the scope (no
credentials in the request). In the response the user client receives the time
limited URL of the IDP that the user must open in the browser. When
authentication in the browser is completed the user is redirected to the
callback that the user also sent in the initial request (most likely on the
localhost). User client is catching this callback containing the OIDC
authorization code. Afterwards this code is being sent to the Keystone together
with the authentication state and the user receives regular scoped or unscoped
Keystone token.
