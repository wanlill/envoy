#pragma once

#include <cstdint>
#include <string>

#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"
#include "envoy/secret/secret_callbacks.h"

#include "source/common/common/logger.h"
#include "source/common/network/transport_socket_options_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace MagicTls {

class MagicTlsSocketFactory : public Network::CommonTransportSocketFactory,
                               public Secret::SecretCallbacks,
                               Logger::Loggable<Logger::Id::config> {
public:
  MagicTlsSocketFactory(Network::TransportSocketFactoryPtr cleartext_socket_factory,
                         Network::TransportSocketFactoryPtr tls_socket_factory);

  ~MagicTlsSocketFactory() override;

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options) const override;
  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options, int n) const;
  bool implementsSecureTransport() const override { return true; }
  bool supportsAlpn() const override { return true; }

  // Secret::SecretCallbacks
  void onAddOrUpdateSecret() override;

private:
  Network::TransportSocketFactoryPtr cleartext_socket_factory_;
  Network::TransportSocketFactoryPtr tls_socket_factory_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
