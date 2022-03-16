#include "source/extensions/transport_sockets/magic_tls/socket_factory.h"
#include "source/extensions/transport_sockets/tls/ssl_socket.h"

#include "envoy/stats/scope.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace MagicTls {

MagicTlsSocketFactory::MagicTlsSocketFactory(
    Network::TransportSocketFactoryPtr cleartext_socket_factory,
    Network::TransportSocketFactoryPtr tls_socket_factory, Stats::Scope& stats_scope)
    : cleartext_socket_factory_(std::move(cleartext_socket_factory)),
      tls_socket_factory_(std::move(tls_socket_factory)), stats_scope_(stats_scope) {}

void MagicTlsSocketFactory::onAddOrUpdateSecret() {
  dynamic_cast<Tls::ClientSslSocketFactory*>(tls_socket_factory_.get())->onAddOrUpdateSecret();
}

Network::TransportSocketPtr MagicTlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options, int n) const {
  if (n % 2 == 0) {
    return tls_socket_factory_->createTransportSocket(options);
  }
  return cleartext_socket_factory_->createTransportSocket(options);
}

} // namespace MagicTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
