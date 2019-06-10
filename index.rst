..
  Technote content.

  Use the following syntax for sections:

  Sections
  ========
  Subsections
  -----------
  Subsubsections
  ^^^^^^^^^^^^^^
  .. figure:: /_static/filename.ext
     :name: fig-label

     Caption text.

:tocdepth: 1

.. Please do not modify tocdepth; will be fixed when a new Sphinx theme is shipped.

.. sectnum::

.. TODO: Delete the note below before merging new content to the master branch.

.. note::

   **This technote is not yet published.**

   Implementation of the LSST LSP Authentication and Authorization System


Building Blocks
===============

Nginx
-----

Nginx is a ubiquitous web server. It's one of the two most common implementations for the ingress
controller of Kubernetes - the other being the GLBC, the GCE ingress controller available in
Google's GKE kubernetes offering. We standardize on Nginx as the ingress controller in all
environments - even when deploying to GKE.

All web traffic to our LSP aspects for a given LSP instance must go through a single Nginx ingress
deployment. The Nginx ingress deployment functions as a reverse proxy to all web services.

Nginx has a powerful feature in the form of the
```auth_request`` <https://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`__ directive
within the ``ngx_http_auth_request_module``, that is built by default in all major distributions of
Nginx, and supported by the Nginx Kubernetes ingress controller annotations. The ``auth_request``
directive enables authorization based on the result of a subrequest - a representative HTTP request
of the original HTTP request being serviced by Nginx, sent to an arbitrary service. When used inside
Kubernetes via the Nginx ingress controller, the ingress controller will send additional headers to
fully describe the original HTTP request, including request method, URI, IP address, and more,
depending on the version of the ingress controller. Newer versions of the ingress controller (>
0.17.0) have better support for advanced ``auth_request`` configuration that will likely be useful,
such as subrequest caching. For example, subrequests could be cached, by a cookie or HTTP header
(e.g. a token), for 30 seconds and reduce the load on the backend servicing the ``auth_request``.

oauth2_proxy
------------

oauth2_proxy is a popular reverse proxy that provides authentication using OAuth2 Providers (Google,
GitHub, most importantly OpenID Connect) to validate accounts by email. oauth2_proxy has been around
for a long time under `the bitly GitHub organization <https://github.com/bitly/oauth2_proxy>`__, but
early in 2018 development had stagnated. Since then, it's been forked a few times, with the most
prolific successors being the `pusher/oauth2_proxy fork <https://github.com/pusher/oauth2_proxy>`__
and `buzzfeed/sso <https://github.com/buzzfeed/sso>`__. Buzzfeed's SSO implements many additional
features via an additional service that is not available in the core of the oauth2_proxy code,
though it's proxy component lags development of the pusher fork.

In general, all of these services are building blocks or variations of the Identity-Aware Proxy,
known as `BeyondCorp <https://cloud.google.com/beyondcorp>`__, as pioneered by Google.

oauth2_proxy can be used in two primary modes. The first mode is an actual proxy - all requests go
*through* oauth2_proxy, before it sends along to downstream services. oauth2_proxy will
inspect a cookie to determine if a user is authenticated. If a user is unauthenticated, oauth2_proxy
will perform redirects as appropriate to the providers, of which your instance of oauth2_proxy must
be a client of.

Once login is verified, cookies are stored, and the requests are *forwarded* to the downstream
services. Importantly, in proxy mode, oauth2_proxy is usually configured to set additional headers
(via ``-pass-authorization-header``, ``-pass-user-headers``, and more) which are also forwarded to
the downstream services, typically username, email, and the oauth2 tokens the user used to
authenticate.

For another mode of operation, oauth2_proxy also has an additional endpoint, the ``/oauth2/auth``
endpoint, which will return a 202 if the user is authenticated. This endpoint can be used directly
with the ```auth_request`` <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`__
directive of Nginx. These requests are always ``GET`` requests to the specified endpoint -
``/oauth2/auth`` in the basic oauth2 configuration. Once login is finished, cookies are stored, and
the requests are returned to the upstream service (Nginx). Importantly, in using the
``auth_request`` mode, oauth2_proxy is usually configured to set additional headers which are
*returned* to the upstream service (``-set-authorization-header``, ``-set-xauthrequest``), typically
username, email, and the oauth2_tokens the user used to authenticate - similar to those in proxy
mode, but with slightly different names.

In both modes, oauth2_proxy always returns a ``Set-Cookie`` header on successful authentication,
historically a serialized oauth2_proxy Session object. Part of the value of that cookie is encrypted
by oauth2_proxy - fields the fields representing that Session object, consisting of OAuth2 tokens,
username, and email. The rest of that token consists of a session expiration and an HMAC signature on
the encrypted token and expiration. On repeated requests, the HMAC signature is verified so
oauth2_proxy can verify the expiration hasn't been tampered with. Once verified, it will decrypt the
encrypted data into the Session object. Taking into account the expiration, oauth2_proxy may also
refresh the access token with a refresh token, if available and oauth2_proxy configured, which
typically results in a new ``Set-Cookie`` header.

The use of cookies for storage means oauth2_proxy does not need a database or file system to store
cookies, and the encryption of the cookies means that the user also cannot access the original
tokens. It is during the lifetime of a user's request that tokens are unencrypted.


Implementation
==============

CILogon - an OpenID connect provider
------------------------------------

`CILogon <https://www.cilogon.org>`__ functions as our OpenID Connect provider. CILogon is further
described in `DMTN-094 <https://dmtn-094.lsst.io>`__ and elsewhere, but there are a few important
properties to reiterate. First off, CILogon is a meta-provider that reduces the complexities of
Shibboleth and OAuth2 from other providers (such as Universities, GitHub, Google, etc...) to a set
of common claims in a JWT. In the context of the LSP, oauth2_proxy is a CILogon client. It's no
ordinary client, however, as the CILogon team enabled a special configuration for the OAuth2
``client_id`` we use for CILogon. This special configuration will augment the JWT OIDC identity
token's claims, as well as the OIDC ``/userinfo`` JSON endpoint, with additional information when
the user's external identity can be associated to the user's LSST identity. It does this primarily
through LDAP lookups. Again, this account is fundamentally an account at NCSA with a username, Unix
UID, and a set of groups a user is a member of. When the user's external identity is not associated
with an LSST identity, CILogon still *authenticates* the user, and subsequently, oauth2_proxy still
authenticates the user, but that additional claims are not there. oauth2_proxy itself currently has
no way of denying authentication based on the claims in a JWT OIDC identity token.

oauth2_proxy
------------

We've forked oauth2_proxy and have made three important changes - JWT Bearer Passthrough and Server
Session Store, and an additional change integrating the two together.

This is a description of those features.

JWT Bearer Passthrough
^^^^^^^^^^^^^^^^^^^^^^

The first, and most important for APIs, is JWT Bearer Passthrough. JWT Bearer Passthrough allows
tokens, typically JWT tokens (except when using `Server Session Store <#server-session-store>`__),
in the Authorization HTTP header of the form ``Authorization: Bearer [token]``, as well as a
fallback mechanism to detect if a token is actually encoded in the HTTP Basic header, for clients
that implement HTTP Basic authentication. The fallback mechanism is based on `GitHub's
implementation <https://github.blog/2012-09-21-easier-builds-and-deployments-using-git-over-https-and-oauth/#using-oauth-with-git>`__
to enable easier integration with clients that can speak HTTP Basic, but don't support modifying the
``Authorization`` header as appropriate. For those clients, you can simply use the token for the
username and either a blank password or the string ``x-oauth-basic`` when cloning a repository. Our
implementation also accepts ``x-oauth-basic`` as the username with the tokens as the password.

Importantly, the JWT Bearer Passthrough implementation also allows you to specify additional
Providers which oauth2_proxy can trust for verifying the token. A provider in this context MUST have
a discoverable JWKS, either through the discoverable URL in the ``jwks`` attribute on
``.well-known/openid-configuration``, or directly in ``.well-known/jwks.json``.

Server Session Store
^^^^^^^^^^^^^^^^^^^^

In the course of implementing authentication, we ran into issues with large cookies. The token we
receive from our Provider, CILogon, includes quite a bit of information about the user's account at
NCSA, and a refresh token. It's was common for the oauth2_proxy cookie to exceed 4kB, which tends to
cause a lot of issues with passing tokens to the backend services. This was how we actually ended up
at the pusher fork of ``oauth2\_proxy`` initially, as it had large cookie support by splitting into
multiple cookies. That implementation had issues with Nginx during the refresh, which occurred every
15 minutes. Another issue we ran across, even if the cookies work, is integration with legacy
clients. The Apple WebDAVFS implementation, via mount_webdav, for example, supports HTTP Basic
authentication but the username and password cannot exceed 256 characters. In addition to this, 4kB
can add up to a non-trivial amount of traffic over the wire if an application relies heavily on
small requests. These considerations led us to implement a server-side session store.

In the Server Cookie Store, instead of returning the actual oauth2_proxy cookie, we return a ticket
to the to that cookie.

A ticket is composed of:

``{CookieName}-{ticketID}.{secret}``

Where:

-  the \ ``CookieName`` is the OAuth2 cookie name (``_oauth2_proxy`` by default, but we set it to
   ``oauth2_proxy`` in our deployment)
-  the ``ticketID`` is a 128-bit random number, hex-encoded
-  the ``secret`` is a 128-bit random number, base64 encoded

``{CookieName}-{ticketID}.{secret}``

The pair of ``{CookieName}-{ticketID}`` comprises a ticket handle, and thus, a natural storage key.

When enabled, oauth2_proxy will encrypt the session state using the secret, and store the encrypted
session with the secret in a store using the handle, as the key. It then sends the ticket back to
the user as the cookie. In later requests, the ticket is decoded to the handle and secret, which are
used to lookup and decrypt the session state.

As we are adding a Server Session Store, we have attempted to preserve an aspect of oauth2_proxy
without the Server Session Store - the tokens are only unencrypted during the lifetime of a user's
request, and the user is not allowed access to the unencrypted OAuth tokens. An admin with access to
the session store cannot recover the tokens.

One server session store has be implemented - a Redis backend. Tokens are stored with an expiration
via the Redis ``SETEX`` command. The expiration of the is the value of the ``-cookie-expire``
parameter for oauth2_proxy.

Tickets and Bearer Passthrough Integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The two features are independent of each other, and we are working to upstream them.

However, integrating the two features together allows us to use tickets in addition to JWT tokens
for the JWT Bearer Passthrough. This feature is used by us to write sessions to the Redis session
store and return the associated ticket, via an additional application. We use this as a method for
implementing API tokens. Our `JWT Authorizer <#jwt-authorizer>`__ application implements this
feature.

We intend to try to upstream this feature, but if we are unable to, we believe the complexity of
maintaining this feature is low, as the change is very small.


JWT Authorizer
--------------

Before we started using the road of oauth2_proxy, we initially built a simple JWT authorizer
application that would merely verify JWT's in the ``Authorization`` HTTP header. This was also used
with the ``auth_request`` module, with the initial implementation forked from the `SciTokens Nginx
token authorizer <https://github.com/scitokens/nginx-scitokens>`__, which was also based on the
Nginx ``auth_request`` method for authorizing a request. The SciTokens example repo was using a
capabilities-based authorization method oriented around files (with a goal of implementing a
capabilities-based WebDAV server) - which didn't quite fit our capabilities-based API access model
we planned to implement. So we worked on modifying it a bit. Eventually, we came to a point where we
had an authorizer that would allow a service, such as the LSP Portal application, use an auth URI
for the authorizer that included the capability the portal required, which is ``exec:portal``. A
simplified form of the Nginx configuration would be as follows:

::

       location /portal {
           auth_request /auth-portal;
           proxy_pass http://portal:8080/portal;
           ...;
       }

       location /auth-portal {
           internal;
           proxy_pass http://jwt-authorizer:8080/auth?capability=exec:portal
           proxy_pass_request_body off;
           proxy_set_header Content-Length "";
           proxy_set_header X-Original-URI $request_uri;
           proxy_set_header X-Original-Method $request_method;
           ...;
       }

During the course of a request to any URI under ``/portal``, the original headers from that request
are forwarded to the ``/auth`` endpoint for the JWT Authorizer application, in addition to those
set. An additional ``capability`` argument, with value ``exec:portal``, is supplied to with auth URI
- this allows us to reuse the same web application for different capability checks. When the request
is received by JWT Authorizer, the token in the ``Authorization`` header is validated (signature
checked), and then the token is checked, directly or indirectly, for a claim representing
``exec:portal``. This claim is directly checked by looking for ``exec:portal`` in the ``scope``
claim of the token. Indirectly, it may be found through a group association to the value of the
``isMemberOf`` claim, with a group that represents that capability. Those group names are
configurable, but here is an example of that configuration:

::

       GROUP_MAPPINGS:
           exec:portal: ["lsst_int_lsp_int_portal_x"]
           exec:notebook: ["lsst_int_lsp_int_nb_x"]
           read:tap: ["lsst_int_lsp_int_tap_r"]
           read:tap/user: ["lsst_int_lsp_int_tap_usr_r"]
           read:tap/history: ["lsst_int_lsp_int_tap_hist_r"]
           read:image: ["lsst_int_lsp_int_img_r"]
           read:workspace: ["lsst_int_lsp_int_ws_r"]
           read:workspace/user: ["lsst_int_lsp_int_ws_usr_r"]

With this configuration as an example, a user's HTTP request, against a service which requires the
``read:image`` capability, may be authorized if that capability exists in the ``scope`` claim
string, or if the user is in a that maps to that claim, ``lsst_int_lsp_int_img_r`` according to this
example. This dual approach allows authorization based on identity (via Groups) or capability. The
first is more useful in web applications, the second is more useful for API access.

Token Issuer
------------

In the course of implementation, we found CILogon unable to implement all desired token semantics
for the use cases we wanted. There were a few important semantics we wanted to be built into the system.

The types of tokens we want to be issued include:

-  Reissued tokens based on the CILogon token, which are useful for web applications. These live for
   24 hours. 
-  API tokens via a Token download interface
-  Internally reissued tokens for satisfying the `Token Acceptance
   Guarantee <#token-acceptance-guarantee>`__

It would not be reasonable for CILogon to implement these capabilities for
us. As such, we've implemented a Token Issuer. In our implementation,
the Token Issuer is integrated in with the JWT Authorizer.


Reissued Tokens
^^^^^^^^^^^^^^^

The first type of token reissuance happens only once.

During login, when a user first authenticates to oauth2_proxy, oauth2_proxy writes out the session
state to the Redis Session Store, issues a ``Set-Cookie`` header, and sends the request to the JWT
Authorizer. The JWT Authorizer sees the issuer was CILogon, and reissues the token - by writing out an
updates Session state to the Redis Session Store, using the same handle from the oauth2_proxy
ticket.

In subsequent requests, oauth2_proxy will decode that session state and pass those updated tokens
through to JWT Authorizer. JWT Authorizer always performs authorization based on those tokens.

The audience in the ``aud`` claim for these tokens is always the full hostname, e.g.
``https://lsst-lsp.ncsa.illinois.edu``.

Token Download Interface - API Tokens
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

JWT Authorizer exports a simple web interface, under the
``/auth/tokens`` endpoint, which can be used to issue API tokens. When
a user visits that endpoint, they will see a list of tokens that have
been previously issued to them. A user may issue a new token,
selecting the capabilities that token requires. By virtue of this web
interface also being protected by the JWT Authorizer itself, the web
interface has access to data from the `Reissued Token
<#reissued-tokens`__, such as the user's UID and email. That
information is included in the API token when issued.

The audience in the ``aud`` claim for these tokens is always the full hostname, e.g.
``https://lsst-lsp.ncsa.illinois.edu``.


Token Acceptance Guarantee
^^^^^^^^^^^^^^^^^^^^^^^^^^

Our APIs service long-running requests. If one API service was to
accept a token one minute before the token was issued, perform an
action, and then 2 minutes later call another API service, the
token would have expired by then and the action would fail.

To mitigate this, fulfilling a policy that requires such actions
succeed, we implement the re-issuance locally in JWT
Authorizer. Tokens reissued in this manner are called internal
tokens. Internal tokens are never considered for re-issuance.

The audience in the ``aud`` claim for these tokens is always the full hostname, with a ``/api``
suffix, e.g. ``https://lsst-lsp.ncsa.illinois.edu/api``.


``.well-known``'s
-----------------

We have one ``.well-known`` endpoint, ``.well-known/jwks.json``, which
is a `JWKS file <https://tools.ietf.org/html/rfc7517>`__ with the keys
necessary for the `Token Issuer <#token-issuer>`__. This file is used
by oauth2_proxy to verify verify tokens.


Usage
=====


Capabilities
------------

For securing a web application or an API, it's important to first know
the capabilities you want to require.

In the LSP, capabilities are used to gate access to services, and are
typically based on the data or resources a service makes
available.

For more information, consult the `Data and Services classifications
section of DMTN-094
<https://dmtn-094.lsst.io/#data-and-service-classifications>`__.

The following capabilities are defined based on access to LSST data
and LSP aspects.

+------------------------------------------------------------------------------------------------+----------------------+
| Resources                                                                                      | Capability           |
+================================================================================================+======================+
| Image Access -  Read images from the SODA and other image retrieval interfaces                 | read:image           |
+------------------------------------------------------------------------------------------------+----------------------+
| Image Access (Metadata) - Read image metadata from SIA and other image interfaces              | read:image/md        |
+------------------------------------------------------------------------------------------------+----------------------+
| Table Access (DR, Alerts) - Execute SELECT queries in the TAP interface on project datasets    | read:tap             |
+------------------------------------------------------------------------------------------------+----------------------+
| Table Access - (Transformed EFD) - Execute SELECT queries in the TAP interface on EFD datasets | read:tap/efd         |
+------------------------------------------------------------------------------------------------+----------------------+
| Table Access (User and Shared) - Execute SELECT queries in the TAP interface on your data      | read:tap/user        |
+------------------------------------------------------------------------------------------------+----------------------+
| Table Access (User and Shared) - Upload tables to your database workspace                      | write:tap/user       |
+------------------------------------------------------------------------------------------------+----------------------+
| User Query History - Read the history of your TAP queries.                                     | read:tap/history     |
+------------------------------------------------------------------------------------------------+----------------------+
| File/Workspace Access - Read project datasets from the file workspace                          | read:workspace       |
+------------------------------------------------------------------------------------------------+----------------------+
| File/Workspace Access (User/Shared) - Read the data in your file workspace                     | read:workspace/user  |
+------------------------------------------------------------------------------------------------+----------------------+
| File/Workspace Access (User/Shared) - Write data to your file workspace                        | write:workspace/user |
+------------------------------------------------------------------------------------------------+----------------------+
| Portal - Use the Portal (also needed for JupyterHub plugin)                                    | exec:portal          |
+------------------------------------------------------------------------------------------------+----------------------+
| Notebook - Use the Notebook                                                                    | exec:notebook        |
+------------------------------------------------------------------------------------------------+----------------------+

Two additional capabilites are defined. Unlike the previous
capabilities, these capabilities are not strictly derived from
previously defined LSST data or specific LSP aspects, but they are
required to secure web applications behind JWT Authorizer.

+---------------------------------------------------------------------+------------+
| Resources                                                           | Capability |
+=====================================================================+============+
| User (Token Download Interface) - Access user-oriented interfaces   | exec:user  |
+---------------------------------------------------------------------+------------+
| Admin Services (ElasticSearch) - Access admin-oriented interfaces   | exec:admin |
+---------------------------------------------------------------------+------------+


Configuring JWT Authorizer
^^^^^^^^^^^^^^^^^^^^^^^^^^

JWT Authorizer should be configured with a group mapping. That group
mapping may need to be updated per-instance.

There should be a mapping to one or more groups for every `capability
<#capabilities>`__. In early stages of LSP development, we will
coarsely define these mappings - mappings will map to one or two
groups, such as ``lsst_int_lspdev``, for example. As time goes on, we
expect groups to be created with more granularity. This will allow us
to gate service to a resource by removing a user from a fine-grained
group.

Mapping all capabilities to a single group - an example of
coarse-grained mapping:

::
   
       GROUP_MAPPINGS:
           exec:portal: ["lsst_int_lspdev"]
           exec:notebook: ["lsst_int_lspdev"]
           read:tap: ["lsst_int_lspdev"]
           read:tap/user: ["lsst_int_lspdev"]
           read:tap/history: ["lsst_int_lspdev"]
           read:image: ["lsst_int_lspdev"]
           read:workspace: ["lsst_int_lspdev"]
           read:workspace/user: ["lsst_int_lspdev"]

Mapping each capability to a well-defined group - an example of
fine-grained mapping:

::

       GROUP_MAPPINGS:
           exec:portal: ["lsst_int_lsp_int_portal_x"]
           exec:notebook: ["lsst_int_lsp_int_nb_x"]
           read:tap: ["lsst_int_lsp_int_tap_r"]
           read:tap/user: ["lsst_int_lsp_int_tap_usr_r"]
           read:tap/history: ["lsst_int_lsp_int_tap_hist_r"]
           read:image: ["lsst_int_lsp_int_img_r"]
           read:workspace: ["lsst_int_lsp_int_ws_r"]
           read:workspace/user: ["lsst_int_lsp_int_ws_usr_r"]


Securing Web Applications
-------------------------

Notebook Example
^^^^^^^^^^^^^^^^

Annotations for securing the notebook. Since the JupyterHub
application has it's own authorization framework, we manually set an
additional header, ``X-Portal-Authorization``, with the token.
::

  metadata:
    annotations:
      kubernetes.io/ingress.class: nginx
      nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
      nginx.ingress.kubernetes.io/auth-url: https://lsst-lsp-int.ncsa.illinois.edu/auth?capability=exec:notebook
      nginx.ingress.kubernetes.io/configuration-snippet: |
        auth_request_set $auth_token $upstream_http_x_auth_request_token;
        proxy_set_header X-Portal-Authorization "Bearer $auth_token";
        error_page 403 = "https://lsst-lsp-int.ncsa.illinois.edu/oauth2/start?rd=$request_uri";

ElasticSearch Example
^^^^^^^^^^^^^^^^^^^^^

Annotations for securing an admin application. The backend expects the
username in the ``X-Remote-User`` header, the email in the
``X-Auth-Request-Email`` header, the token in the
``X-Auth-Request-Token`` header. JWT Authorizer makes the username
available via the ``X-Auth-Request-Uid`` header, so we manually
rewrite that with a configuration snippet:

::
  metadata:
    annotations:
      kubernetes.io/ingress.class: nginx
      nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token, X-Auth-Request-Email, X-Auth-Request-Uid
      nginx.ingress.kubernetes.io/auth-url: https://lsst-lsp-int.ncsa.illinois.edu/auth?capability=exec:admin
      nginx.ingress.kubernetes.io/configuration-snippet: |
        auth_request_set $remote_user $upstream_http_x_auth_request_uid;
        proxy_set_header X-Remote-User "$remote_user";
        error_page 403 = "https://lsst-lsp-int.ncsa.illinois.edu/oauth2/start?rd=$request_uri";


Securing Web APIs
-----------------

Most applications will just use the token to access, and may decode
that token for some information about the user.

Annotations for protecting an API endpoint with the ``read:image`` capability for the
domain ``lsst-lsp-int.ncsa.illinois.edu``. All requests to the backend
will have the ``X-Auth-Request-Token`` header set. Unauthorized
requests will redirect to the oauth2_proxy initialization, which only
works within browser.


::

  metadata:
    annotations:
      kubernetes.io/ingress.class: nginx
      nginx.ingress.kubernetes.io/auth-request-redirect: $request_uri
      nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
      nginx.ingress.kubernetes.io/auth-url: https://lsst-lsp-int.ncsa.illinois.edu/auth?capability=read:image
      nginx.ingress.kubernetes.io/configuration-snippet: |
        error_page 403 = "https://lsst-lsp-int.ncsa.illinois.edu/oauth2/start?rd=$request_uri";


.. .. rubric:: References

.. Make in-text citations with: :cite:`bibkey`.

.. .. bibliography:: local.bib lsstbib/books.bib lsstbib/lsst.bib lsstbib/lsst-dm.bib lsstbib/refs.bib lsstbib/refs_ads.bib
..    :style: lsst_aa
