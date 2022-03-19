load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    # TLS is core functionality.
    visibility = ["//visibility:public"],
    deps = [
        ":socket_factory_lib",
        "//envoy/network:transport_socket_interface",
        "//envoy/registry",
        "//envoy/server:transport_socket_config_interface",
        "//source/extensions/transport_sockets/raw_buffer:config",
        "//source/extensions/transport_sockets/tls:config",
        "@envoy_api//envoy/extensions/transport_sockets/magic_tls/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "socket_factory_lib",
    srcs = ["socket_factory.cc"],
    hdrs = ["socket_factory.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//envoy/network:connection_interface",
        "//envoy/network:transport_socket_interface",
        "//envoy/secret:secret_callbacks_interface",
        "//envoy/stats:stats_macros",
        "//source/common/network:transport_socket_options_lib",
        "//source/extensions/transport_sockets/tls:ssl_socket_lib",
    ],
)
