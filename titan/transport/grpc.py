"""gRPC Transport — Exploit gRPC services via server reflection.

Uses gRPC server reflection to discover services and methods,
then sends crafted requests to test for vulnerabilities.

Features:
  - Server reflection to discover services/methods
  - Unary RPC support
  - Metadata injection (for auth testing)
  - Deadline/timeout control

Requirements: pip install grpcio grpcio-reflection grpcio-tools
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
)

logger = logging.getLogger(__name__)


class GrpcTransport(Transport):
    """gRPC transport with server reflection for service discovery.

    Usage:
        transport = GrpcTransport()
        response = await transport.send(AttackRequest(
            url="localhost:50051/grpc.health.v1.Health/Check",
        ))
    """

    PROTOCOLS = {TransportProtocol.GRPC}

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._identity = TransportIdentity(protocol="grpc")

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Send a gRPC request.

        URL format: host:port/service.method
        Example: localhost:50051/grpc.health.v1.Health/Check

        If no service path is provided, uses reflection to discover services.
        The request body is sent as raw bytes (for generic invocation).
        """
        start = time.time()

        try:
            import grpc

            # Parse target from URL
            url = request.url
            if "://" in url:
                url = url.split("://", 1)[1]

            # Split host:port from service path
            parts = url.split("/", 1)
            target = parts[0]
            service_path = parts[1] if len(parts) > 1 else ""

            # Create channel
            channel = grpc.insecure_channel(target)

            try:
                # Wait for channel to be ready
                grpc.channel_ready_future(channel).result(timeout=min(self.timeout, 5))

                if service_path:
                    # Call the specific service method
                    response_bytes = self._call_unary(channel, service_path, request)
                    return AttackResponse(
                        status=200 if response_bytes else 0,
                        headers={},
                        body=response_bytes or b"",
                        elapsed=time.time() - start,
                        url=request.url,
                        protocol="grpc",
                    )
                else:
                    # Use reflection to discover services
                    services = self._reflect(channel)
                    return AttackResponse(
                        status=200,
                        headers={"content-type": "application/json"},
                        body=json.dumps(services, indent=2).encode(),
                        elapsed=time.time() - start,
                        url=request.url,
                        protocol="grpc",
                    )
            finally:
                channel.close()

        except ImportError:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="grpc",
                error="grpcio not installed: pip install grpcio grpcio-reflection",
            )
        except Exception as e:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="grpc",
                error=str(e),
            )

    def _reflect(self, channel) -> list[dict]:
        """Use server reflection to discover services."""
        try:
            from grpc_reflection.v1alpha import reflection_pb2
            from grpc_reflection.v1alpha import reflection_pb2_grpc

            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            # Request list of services
            request = reflection_pb2.ServerReflectionRequest(
                list_services=""
            )

            services = []
            responses = stub.ServerReflectionInfo(iter([request]))
            for response in responses:
                if response.HasField("list_services"):
                    for svc in response.list_services.service:
                        services.append({"service": svc.name})
                elif response.HasField("file_by_filename"):
                    services.append({"file": response.file_by_filename})

            return services
        except ImportError:
            logger.warning("grpcio-reflection not installed")
            return []
        except Exception as e:
            logger.debug(f"gRPC reflection failed: {e}")
            return []

    def _call_unary(self, channel, service_path: str, request: AttackRequest) -> bytes | None:
        """Call a unary RPC method with raw bytes.

        This is a best-effort generic invocation. For proper protobuf
        serialization, the caller should provide serialized protobuf bytes
        in request.body.
        """
        try:
            # Generic invocation — raw bytes in, raw bytes out
            # The caller is responsible for serializing the protobuf request
            method = channel.unary_unary(
                f"/{service_path}",
                request_serializer=lambda x: x if isinstance(x, bytes) else x.encode(),
                response_deserializer=lambda x: x,
            )
            result = method(request.body or b"", timeout=self.timeout)
            return result
        except Exception as e:
            logger.debug(f"gRPC call to {service_path} failed: {e}")
            return None

    async def connect(self, target: TargetDescriptor) -> None:
        """Verify gRPC target is reachable."""
        try:
            import grpc

            channel = grpc.insecure_channel(f"{target.host}:{target.port}")
            try:
                grpc.channel_ready_future(channel).result(timeout=5)
                logger.info(f"gRPC target reachable: {target.host}:{target.port}")
            finally:
                channel.close()
        except ImportError:
            logger.warning("grpcio not installed")
        except Exception as e:
            logger.warning(f"gRPC target unreachable: {e}")
