1.23.0 (Pending)
================

Incompatible Behavior Changes
-----------------------------
*Changes that are expected to cause an incompatibility if applicable; deployment changes are likely required*

* tls-inspector: the listener filter tls inspector's stats ``connection_closed`` and ``read_error`` are removed. The new stats are introduced for listener, ``downstream_peek_remote_close`` and ``read_error`` :ref:`listener stats <config_listener_stats>`.

Minor Behavior Changes
----------------------
*Changes that may cause incompatibilities for some users, but should not for most*

* tls: if both :ref:`match_subject_alt_names <envoy_v3_api_field_extensions.transport_sockets.tls.v3.CertificateValidationContext.match_subject_alt_names>` and :ref:`match_typed_subject_alt_names <envoy_v3_api_field_extensions.transport_sockets.tls.v3.CertificateValidationContext.match_typed_subject_alt_names>` are specified, the former (deprecated) field is ignored. Previously, setting both fields would result in an error.
* tls: removed SHA-1 cipher suites from the server-side defaults.
* dns: added ``envoy.reloadable_features.cares_accept_enodata`` to allow propagating DNS responses with no records back to STRICT_DNS clusters.

Bug Fixes
---------
*Changes expected to improve the state of the world and are unlikely to have negative effects*

Removed Config or Runtime
-------------------------
*Normally occurs at the end of the* :ref:`deprecation period <deprecated>`

New Features
------------
* dns_resolver: added :ref:`include_unroutable_families<envoy_v3_api_field_extensions.network.dns_resolver.apple.v3.AppleDnsResolverConfig.include_unroutable_families>` to the Apple DNS resolver.
* ext_proc: added support for per-route :ref:`grpc_service <envoy_v3_api_field_extensions.filters.http.ext_proc.v3.ExtProcOverrides.grpc_service>`.

Deprecated
----------
