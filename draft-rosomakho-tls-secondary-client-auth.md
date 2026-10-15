---
title: "Secondary Client Authentication in TLS 1.3"
abbrev: "Secondary Client Authentication"
category: std
updates: "9846, 9001, 9113"

docname: draft-rosomakho-tls-secondary-client-auth-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - tls
 - client authentication
 - post-handshake authentication
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "yaroslavros/tls-secondary-client-auth"
  latest: "https://yaroslavros.github.io/tls-secondary-client-auth/draft-rosomakho-tls-secondary-client-auth.html"

author:
 -
    fullname: Yaroslav Rosomakho
    organization: Zscaler
    email: yrosomakho@zscaler.com
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "k.tirumaleswar_reddy@nokia.com"
 -
    fullname: Rifaat Shekh-Yusef
    organization: Ciena
    country: Canada
    email: rifaat.s.ietf@gmail.com
 -
    fullname: Hannes Tschofenig
    organization: University of the Bundeswehr Munich
    abbrev: UniBw M.
    country: Germany
    email: "hannes.tschofenig@gmx.net"

normative:
  H2:
    =: RFC9113
    display: HTTP/2

informative:

--- abstract

Some deployments authenticate a client using two certificates, such as
one identifying a device and another identifying its user. This
document defines the `secondary_client_certificate` TLS flag to
negotiate one additional client authentication exchange as part of
connection establishment. The server sends an additional
CertificateRequest immediately after its Finished, and the client
responds after its own handshake Finished and before sending
application data. Either certificate response can be empty, and the
server determines whether the resulting authentication state satisfies
its policy.

This document updates RFC 9846 to permit the additional request before
the server receives the client's Finished. It also updates RFCs 9001
and 9113 to permit this negotiated exchange with QUIC and HTTP/2.

--- middle

# Introduction

TLS 1.3 {{!TLS=RFC9846}} supports client certificate authentication
during the handshake and post-handshake authentication (PHA). Some
deployments need two client credentials when establishing a connection.
For example, a VPN over TLS can authenticate both a managed device and
the user operating it. The server evaluates the credentials together
when deciding what access to grant.

This document defines secondary client authentication: a single
additional client authentication exchange negotiated during the TLS
handshake and completed by the client before it sends application
data. The `secondary_client_certificate` flag, carried in the
`tls_flags` extension {{!TLS-FLAGS=I-D.ietf-tls-tlsflags}}, signals
support in ClientHello and acceptance in the server's handshake
CertificateRequest.

The server sends the secondary CertificateRequest immediately after
its Finished. The client answers the handshake request, sends its
handshake Finished, and then answers the secondary request using PHA.
The secondary request can be sent in the same server flight, avoiding
an additional round trip to request the second credential.

The two requests can specify different certificate-selection criteria.
This document assigns no user or device role to either request. Their
roles are determined by the request parameters, deployment policy, or
an application-specific agreement. Nor does negotiation promise that
the client will supply two non-empty certificate chains: acceptance of
the responses remains a server policy decision.

The exchange is part of establishing the connection's client
authentication context. It is not triggered by an application request,
so the client does not need to correlate it with activity on a
particular application stream. This permits a limited exception to the
PHA restrictions in QUIC and HTTP/2, as specified in {{h2-quic}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The *handshake request* is the CertificateRequest sent before the
server's Finished. The *secondary request* is the additional
CertificateRequest sent immediately after that Finished. The
*handshake Finished* is the client's Finished completing the main TLS
handshake, as distinct from the Finished in its secondary response.

# Overview

A client offers secondary client authentication by including both the
`secondary_client_certificate` flag and the `post_handshake_auth`
extension in its ClientHello. A server accepts by including the flag
in the CertificateRequest message sent during the handshake. Acceptance
commits the server to sending one secondary request and the client to
responding before sending any application data.

{{fig-overview}} shows an exchange in which both client Certificate
messages contain certificates. Braces indicate handshake traffic key
protection; square brackets indicate application traffic key
protection. A CertificateVerify is omitted if its corresponding client
Certificate is empty. An asterisk marks optional server application
data before client authentication.

~~~
Client                                             Server

ClientHello
  + post_handshake_auth
  + secondary_client_certificate
                         -------->
                                               ServerHello
                                     {EncryptedExtensions}
                                      {CertificateRequest
                           + secondary_client_certificate}
                                             {Certificate}
                                       {CertificateVerify}
                                                {Finished}
                                      [CertificateRequest]
                                       [Application Data*]
                         <--------
{Certificate}
{CertificateVerify}
{Finished}
[Certificate]
[CertificateVerify]
[Finished]               -------->

[Application Data]       <------->      [Application Data]
~~~
{: #fig-overview title="Secondary client authentication"}

The server need not wait for either client response before sending
application data. It decides when to send data and when to authorize
application operations according to its policy. A session ticket is
issued only after the server has accepted the authentication state
resulting from both responses.

# Negotiation {#negotiation}

The `secondary_client_certificate` flag is defined for ClientHello and
for the handshake CertificateRequest only. It MUST NOT appear in a
post-handshake CertificateRequest or in a Certificate message.

A client offering the flag MUST also include the `post_handshake_auth`
extension defined in {{Section 4.3.6 of TLS}}. A server supporting this
specification that receives the flag without that extension MUST abort
the handshake with an `illegal_parameter` alert.

A server accepting the offer MUST include the flag in the
CertificateRequest message sent during the handshake. A server MUST NOT
include the flag unless the client offered it. A client receiving the
flag without having offered it MUST abort with an `illegal_parameter`
alert. An endpoint receiving the flag in any other message, including
a post-handshake CertificateRequest, MUST abort with an
`illegal_parameter` alert.

A server that does not accept the offer omits the flag. The client
then follows the otherwise applicable TLS and application-protocol
rules. If local policy requires secondary client authentication for a
full handshake, an endpoint MUST abort the connection when it is not
negotiated. Resuming an accepted authentication state is described in
{{resumption}}.

Secondary client authentication is negotiated only in a full,
certificate-authenticated server handshake. A client MAY offer the
flag while also offering resumption, to allow its use if the server
declines resumption. A server selecting a PSK MUST NOT negotiate the
flag. Resumption behavior is specified in {{resumption}}.

# Secondary Authentication Exchange {#exchange}

## Server Request

Once secondary client authentication has been negotiated, the server
MUST send exactly one secondary request immediately after its
Finished, before any other TLS message or application data. It MAY
send the request in the same flight as its Finished, without waiting
for the client's handshake Finished. This updates the timing rule in
{{Section 4.7.2 of TLS}} for this negotiated exchange only.

The secondary request uses the PHA CertificateRequest format and
application traffic key protection. Its `certificate_request_context`
MUST be non-empty and chosen according to {{Section 4.4.2 of TLS}}.
The two requests independently specify certificate-selection
parameters, including acceptable signature algorithms and, optionally,
certificate authorities or certificate extension filters.

Further post-handshake authentication is governed by the TLS rules and
the application protocol in use. Negotiating secondary client
authentication does not prohibit later PHA where the application
protocol permits it. The restrictions for HTTP/2 and QUIC are specified
in {{h2-quic}}.

## Client Responses

The client MUST respond to the handshake request and send its
handshake Finished before sending its secondary response. It MUST
respond to the secondary request using the PHA authentication messages
defined in {{Section 4.7.2 of TLS}}. The client MUST NOT send
application data until it has sent the Finished ending that response.

If the secondary request has not yet arrived when the client sends its
handshake Finished, the client MUST wait for that request before
sending application data. Receipt of server application data does not
release the client from this obligation.

Either or both client Certificate messages MAY have an empty
`certificate_list`, including when the client has no suitable
certificate or declines to provide one. An empty response omits
CertificateVerify but still includes the applicable Finished. An empty
handshake response does not remove the obligation to send the
secondary response if the connection continues.

Sending the secondary request early does not add it to the main
handshake transcript. For the secondary response, the transcript
consists of the complete main handshake through the client's handshake
Finished, followed by the secondary request and its response messages,
as specified for PHA in {{Section 4.5 of TLS}}. This ordering applies
even when the client receives the secondary request before sending its
handshake Finished. The key schedule and PHA authentication
computations are unchanged.

## Server Policy and Application Data {#policy}

Negotiating secondary client authentication commits the peers to the
exchange, not to accepting any particular credentials. The server
validates any certificates presented, verifies each CertificateVerify
that is present and both Finished messages, and applies its policy to
the resulting combination of identities. Certificate validation and
message verification follow {{Section 4.5 of TLS}}. The server MAY
accept an empty response to either request. If a required certificate
is absent, it MAY abort with a `certificate_required` alert, as in
ordinary client authentication. Other certificate validation failures
follow the TLS rules.

This specification imposes no additional restriction on when the
server sends application data. In particular, the server MAY send
application data after its secondary request without waiting for the
client's responses. Implementations determine when the available
authentication state permits application operations, just as with
ordinary handshake client authentication.

The client sending its secondary Finished does not imply that the
server has accepted either credential. An application requiring
confirmation of authorization obtains it through its own protocol.

# Session Tickets and Resumption {#resumption}

On a connection that negotiated secondary client authentication, a
server MUST NOT issue a NewSessionTicket until it has received and
verified both client Finished messages, processed both certificate
responses, and accepted the resulting authentication state under its
policy. This applies even when one or both responses are empty.

The server MUST associate each such ticket with the accepted
authentication state, including the identities authenticated and any
absence of a credential. This state can be stored at the server or
protected within the ticket. A ticket MUST NOT imply that two
identities were authenticated merely because the flag was negotiated.

A connection resumed from such a ticket uses the authentication state
associated with that ticket. The server MUST NOT request additional
client certificate authentication on the resumed connection. If its
policy requires fresh authentication, the server MUST decline
resumption and perform a full handshake instead. Offering the flag on
a resumption attempt does not by itself require fresh authentication.

This specification does not prohibit 0-RTT on resumed connections. The
usual early-data rules apply, and the server decides whether the
stored authentication state permits the requested early-data
operations. If resumption is declined and secondary client
authentication is negotiated in a full handshake, early data is
rejected and the client follows the send ordering in {{exchange}}.

# Use with HTTP/2 and QUIC {#h2-quic}

HTTP/2 {{H2}} and QUIC {{!QUIC-TLS=RFC9001}} prohibit
post-handshake CertificateRequest messages. Secondary client
authentication provides a limited exception: the request is agreed
during connection establishment, precedes client application data,
and cannot be triggered by an application request on any stream.

When the flag has been negotiated, this document updates
{{Section 9.2.3 of H2}} and {{Section 4.4 of QUIC-TLS}} to permit the
single secondary request and its response specified in {{exchange}}.
A client MUST NOT reject that request solely because it is a
post-handshake CertificateRequest. All other post-handshake
CertificateRequest messages remain prohibited by those specifications,
with their existing protocol-specific error handling. Merely offering
`post_handshake_auth` or offering this flag without server acceptance
does not enable this exception.

For HTTP/2, the client sends its connection preface and subsequent
HTTP/2 frames only after sending its secondary response.

For QUIC, the secondary exchange uses CRYPTO frames at the 1-RTT
encryption level. The client submits the complete secondary response
for transmission before sending application data in STREAM or
DATAGRAM frames. This requirement does not delay ACKs or other QUIC
transport control frames, and does not impose a new packet arrival
ordering requirement. Implementations decide when to deliver or act on
application data according to their authentication policy, as with
ordinary client certificate authentication. Server application-data
timing remains governed by {{policy}}.

# Security Considerations

## Combined Authentication State

The server needs a policy for the combination of credentials, not
merely independent decisions that each certificate chains to a trusted
issuer. For example, a VPN deployment might require that the user be
authorized to use the device represented by the other credential.
Neither possession of two credentials nor their presentation on one
connection establishes that relationship by itself.

The secondary authentication transcript includes the main handshake,
including the first client response. This binds the secondary proof
to that handshake. It does not assign semantic roles to the
credentials or prove that their private keys reside on the same
device. Those properties require deployment-specific controls.

An empty Certificate response contributes no certificate identity.
Servers MUST NOT interpret completion of the exchange as proof that
both requested identities were authenticated.

## Application Access

A server that sends data before accepting the client responses must
account for the possibility that client authentication will fail.
Data already disclosed cannot be recovered by subsequently closing the
connection. Similarly, a server must apply its authorization policy
before acting on application operations that require authenticated
identities.

The mechanism establishes the connection's initial authentication
context. Any later PHA and resulting changes to that context are
governed by the application protocol's rules. HTTP/2 and QUIC continue
to prohibit further TLS post-handshake authentication, as specified in
{{h2-quic}}.

## Resumption State

Resumption relies on the stored authentication state rather than fresh
proofs from the certificate private keys. Ticket lifetimes and
acceptance policy therefore need to account for changes such as
certificate revocation, device removal, or user access withdrawal.
Servers must retain enough information to apply that policy to the
complete authentication state.

Early data additionally remains subject to the replay risks of TLS
0-RTT. Secondary client authentication on the original connection does
not make a resumed connection's early data replay-resistant.

## Resource Use and Privacy

The secondary exchange adds certificate processing and can involve
user interaction. Implementations can apply timeouts and resource
limits while awaiting responses. Negotiation permits only one
secondary exchange, bounding the number of requests made by this
mechanism.

The ClientHello flag exposes support for secondary client
authentication to observers unless protected by Encrypted ClientHello
{{?ECH=RFC9849}}. The flag reveals no credential role or identity.
Both certificate requests and client responses are encrypted. Clients
still decide whether to disclose a certificate in response to either
request.

# IANA Considerations

IANA is requested to add the following entry to the "TLS Flags"
registry established by {{TLS-FLAGS}}:

- Value: TBD
- Flag Name: secondary_client_certificate
- Message: CH, CR
- Recommended: N
- Reference: \[This document\]

The CR use is restricted to the handshake CertificateRequest, as
specified in {{negotiation}}. This document defines no new TLS
extension type or handshake message.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
