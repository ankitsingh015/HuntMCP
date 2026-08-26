---
name: microservices-and-internal-api
description: Microservices and internal-API attack surface -- service-discovery endpoint enumeration (Consul/etcd/Eureka/Zipkin/Nacos), service-to-service JWT weaknesses, gRPC reflection/proto leaks, API gateway path-traversal/header-routing bypasses, exposed message queues (RabbitMQ/Kafka/Redis/Celery), and object-storage default creds. Converted from master-pentest-prompt.md Phase 30. Use when the target's architecture is visibly microservices-based -- an API gateway in front, service-mesh headers, or discovery-service ports exposed.
---

# Microservices & internal API

## When to use

Any target showing microservices-architecture signals: an API gateway
fronting multiple backend services, service-mesh-style headers, or any
of the discovery-service ports below reachable directly.

## Service discovery

Check for exposed: `/actuator`, `/health`, `/info`, `/metrics`, Consul
(port 8500), etcd (port 2379), Eureka, Spring Cloud Gateway
(CVE-2022-22947 RCE), Zipkin, Jaeger, Nacos, Apollo config disclosure --
each of these can leak the internal service topology, config, or
outright grant control.

## Service-to-service auth weaknesses

- An internal auth/JWT-issuing service that doesn't set or check an
  `audience` claim -- a token minted for one internal service can then
  be replayed against another.
- Missing request signing on an internal hop -- once inside the mesh,
  requests between services may be implicitly trusted with no additional
  verification.

## Protocol-level

- **gRPC**: reflection endpoint enabled (leaks the full service
  definition), proto file leaks, an unauthenticated unary API method.
- **HTTP/2 prior-knowledge**: can sometimes bypass controls that were
  only ever enforced on the TLS-negotiated HTTP/2 path.
- **HTTP/2 Rapid Reset on gRPC (CVE-2023-44487-class)**: gRPC runs over
  HTTP/2, so a server that interleaves HEADERS with an immediate
  RST_STREAM per stream races ahead of `MAX_CONCURRENT_STREAMS`
  accounting and exhausts backend resources -- the gRPC transport doesn't
  add its own mitigation beyond whatever the underlying HTTP/2 stack
  patched. DoS is out of scope on almost every program: prefer
  version-matching the `server:` banner / gRPC library version against
  the known-patched list over actually flooding, and only run a live
  reset-flood PoC under explicit written authorization.
- **gRPC-Web / gRPC-JSON transcoding injection**: a gateway
  (Envoy `grpc_json_transcoder`, grpc-gateway, Connect) that translates
  REST/JSON requests into native gRPC calls can apply different -- often
  weaker -- validation on the JSON side than the gRPC-native handler
  does. Smuggle a field or value through the transcoded REST/JSON route
  that the gRPC-native path would have rejected (an admin flag, an
  out-of-range enum, a type the JSON decoder coerces differently than the
  protobuf decoder would). Confirm by sending the same logical request
  both ways -- native `grpcurl` call vs. transcoded JSON POST -- and
  diffing whether one is accepted and the other rejected.

## API gateway bypasses

- **Path-traversal ACL bypass**: reaching an internally-restricted path
  (e.g. Spring Boot Actuator) through a gateway-specific traversal
  pattern like `/;/router`.
- **Header-based routing abuse**: `X-Proto`, `X-Backend`, `X-Service`
  headers that the gateway trusts for routing decisions, which a client
  shouldn't be able to set directly.
- **Consuming an internal API from the public plane**: the gateway
  forwards to an internal service with no separate host allowlist,
  meaning anything reachable through the gateway is effectively exposed.

## Exposed queues and caches

RabbitMQ management UI on 15672 with default `guest:guest`, an
unauthenticated Kafka/Zookeeper instance, exposed Sidekiq or Celery
Flower dashboards, Redis on 6379 with no auth, Memcached on 11211.

## Object storage

MinIO on port 9000 with default credentials.

## Container/orchestration inside the mesh

Docker/K8s ports (2375/2376/6443) reachable from inside the service
network, even if not exposed externally -- see the
`infrastructure-and-protocol` skill for the general container-exposure
checklist; this is the same checklist applied specifically to what's
reachable once you're inside a microservice's network segment.

## SSRF pivot

Use an internal SSRF finding to map the service graph -- `/actuator/env`
on one service is a common way to discover the addresses of others.
