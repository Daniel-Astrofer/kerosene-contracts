# Administrative API contract

Administrative clients are untrusted callers. Possession of `kerosene-rsctl`
or `kerosene-jctl` grants no authority; every service authenticates, authorizes
and audits each request.

Version `0.1.0` defines common error and status responses. JSON uses snake_case
on the wire. Java records use idiomatic field names and must configure Jackson's
snake-case strategy.

Profiles and responses must never contain private keys, tokens, FROST shares,
nonces, macaroons or full financial identity data.
