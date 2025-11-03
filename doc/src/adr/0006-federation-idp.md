# 6. Federation IDP

Date: 2025-11-03

## Status

Accepted

## Context

OIDC requires the server side to know the Identity provider details. Python
Keystone relies on the external software to implement the OIDC flow only
receiving the final data once the flow completes. Certain flows are triggered by
the Service side (i.e. back-channel-logout). In addition to that relying on the
external software does not allow any seld-service for the customer.

v3 currently provides limited OIDC support, but it is not possible to extend it
in a backward compatible way.

As such OIDC support must be implemented natively in Keystone.

## Decision

Keystone implement OIDC support natively without relying on the 3rd-party
software. New APIs must provide self-service capabilities. Identity providers
may be global (i.e. a social login) or dedicated (i.e. private Okta tenant).

A new set of APIs and database tables is added to Keystone for implementing new
functionality. Existing DB constraints MUST not be deleted and only additive
changes can be implemented to allow parallel deployment of python and rust
Keystones for the smooth transition. "Virtual" database entries MUST be inserted
for the old-style identity provider to guarantee the co-existence.

Global/private identity providers are implemented using the optional `domain_id`
attribute. When empty the identity provider is treated as global (shared) and is
correspondingly visible to every user of the cloud. Private IdPs SHOULD be only
visible to the users of the domain. Corresponding rules MUST be implemented on
the policy level to allow customization by the CSP.

The IdP specifies client_id and client_secret (when necessary). `client_secret`
MUST not be retrievable. It can only be set during create or update operations.
It MUST be also possible to specify JWKS urls when the identity provider does
not implement metadata discovery.

## Consequences

New APIs must be implemented in the CLI.
