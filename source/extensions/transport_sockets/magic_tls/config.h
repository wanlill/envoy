#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace MagicTls {

/**
 * Config registration for the MagicTls transport socket factory.
 * @see TransportSocketConfigFactory.
 */
class MagicTlsSocketConfigFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory,
      public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  ~MagicTlsSocketConfigFactory() override = default;
  std::string name() const override { return "envoy.transport_sockets.magic_tls"; }
  Network::TransportSocketFactoryPtr createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(MagicTlsSocketConfigFactory);

} // namespace MagicTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
