#include "source/extensions/transport_sockets/magic_tls/config.h"

#include "source/extensions/transport_sockets/raw_buffer/config.h"
#include "source/extensions/transport_sockets/tls/config.h"
#include "envoy/extensions/transport_sockets/magic_tls/v3/magic_tls.pb.validate.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/transport_sockets/magic_tls/socket_factory.h"

#include <memory>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace MagicTls {

Network::TransportSocketFactoryPtr MagicTlsSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  auto config = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::magic_tls::v3::UpstreamMagicTlsContext&>(
      message, context.messageValidationVisitor());

  RawBuffer::UpstreamRawBufferSocketFactory raw_buffer_socket_factory;
  Tls::UpstreamSslSocketFactory upstream_ssl_socket_factory;

  return std::make_unique<MagicTlsSocketFactory>(
      raw_buffer_socket_factory.createTransportSocketFactory(config.cleartext_socket_config(), context),
      upstream_ssl_socket_factory.createTransportSocketFactory(config.tls_socket_config(), context));
}

ProtobufTypes::MessagePtr MagicTlsSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::magic_tls::v3::UpstreamMagicTlsContext>();
}

REGISTER_FACTORY(MagicTlsSocketConfigFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory){"magic_tls"};

} // namespace MagicTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy