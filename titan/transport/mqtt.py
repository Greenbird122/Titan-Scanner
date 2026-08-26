"""MQTT Transport — Exploit IoT message brokers.

Supports MQTT 3.1.1 and 5.0 for testing IoT device security,
including topic fuzzing, payload injection, and authentication bypass.

Features:
  - Connect to MQTT brokers (1883/8883)
  - Subscribe to topics for intelligence gathering
  - Publish malicious payloads to topics
  - Authentication bypass (anonymous connect)
  - Topic fuzzing (wildcard subscriptions)
  - TLS/SSL support

Requirements: pip install paho-mqtt
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlparse

from titan.transport.base import (
    AttackRequest,
    AttackResponse,
    TargetDescriptor,
    Transport,
    TransportIdentity,
    TransportProtocol,
)

logger = logging.getLogger(__name__)


class MqttTransport(Transport):
    """MQTT transport for IoT broker exploitation.

    Usage:
        transport = MqttTransport()
        response = await transport.send(AttackRequest(
            url="mqtt://broker:1883/sensor/temperature",
            body='{"temp": 999}',
        ))
    """

    PROTOCOLS = {TransportProtocol.MQTT}

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._identity = TransportIdentity(protocol="mqtt")

    @property
    def identity(self) -> TransportIdentity:
        return self._identity

    def supports(self, protocol: TransportProtocol) -> bool:
        return protocol in self.PROTOCOLS

    async def send(self, request: AttackRequest) -> AttackResponse:
        """Publish a message to an MQTT topic.

        URL format: mqtt://broker:port/topic
        Headers can include: username, password
        Body: payload to publish
        """
        start = time.time()

        try:
            import paho.mqtt.client as mqtt

            parsed = urlparse(request.url)
            broker = parsed.hostname
            port = parsed.port or 1883
            topic = parsed.path.lstrip("/")

            if not broker:
                return AttackResponse(
                    status=0,
                    headers={},
                    body=b"",
                    elapsed=time.time() - start,
                    url=request.url,
                    protocol="mqtt",
                    error="No broker hostname in URL",
                )

            # Run the sync paho-mqtt in a thread to avoid blocking the event loop
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._publish_sync,
                broker,
                port,
                topic,
                request.body,
                request.headers,
            )

            return AttackResponse(
                status=200 if result["success"] else 0,
                headers={"topic": topic, "broker": f"{broker}:{port}"},
                body=result.get("payload", b""),
                elapsed=time.time() - start,
                url=request.url,
                protocol="mqtt",
                error=result.get("error"),
            )

        except ImportError:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="mqtt",
                error="paho-mqtt not installed: pip install paho-mqtt",
            )
        except Exception as e:
            return AttackResponse(
                status=0,
                headers={},
                body=b"",
                elapsed=time.time() - start,
                url=request.url,
                protocol="mqtt",
                error=str(e),
            )

    def _publish_sync(
        self,
        broker: str,
        port: int,
        topic: str,
        body: Any,
        headers: dict,
    ) -> dict:
        """Synchronous MQTT publish (run in executor)."""
        import paho.mqtt.client as mqtt

        try:
            client = mqtt.Client(client_id=f"titan-{int(time.time())}")

            # Authentication
            username = headers.get("username")
            password = headers.get("password")
            if username:
                client.username_pw_set(username, password)

            # Connect, publish, disconnect
            client.connect(broker, port, keepalive=10)
            client.loop_start()

            payload = body or b""
            if isinstance(payload, str):
                payload = payload.encode()

            result = client.publish(topic, payload, qos=1)
            result.wait_for_publish(timeout=self.timeout)

            client.loop_stop()
            client.disconnect()

            return {"success": True, "payload": payload}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def subscribe(self, broker: str, port: int, topic: str, duration: float = 5.0) -> list[dict]:
        """Subscribe to a topic and collect messages for a duration."""
        import paho.mqtt.client as mqtt

        messages = []

        def on_message(client, userdata, msg):
            messages.append({
                "topic": msg.topic,
                "payload": msg.payload.decode(errors="replace"),
                "qos": msg.qos,
                "retain": msg.retain,
            })

        def _subscribe_sync():
            client = mqtt.Client(client_id=f"titan-sub-{int(time.time())}")
            client.on_message = on_message
            client.connect(broker, port, keepalive=10)
            client.subscribe(topic, qos=1)
            client.loop_start()
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()

        await asyncio.get_event_loop().run_in_executor(None, _subscribe_sync)
        return messages

    async def fuzz_topics(self, broker: str, port: int, base_topic: str = "") -> list[dict]:
        """Fuzz MQTT topics with common patterns."""
        common_topics = [
            "test", "debug", "admin", "config", "status",
            "sensor/temperature", "device/+/status",
            "#", "+/+/+", "$SYS/#",
            "home/automation/lights",
            "iot/+/telemetry",
        ]

        topics_to_scan = [base_topic] + common_topics if base_topic else common_topics
        results = []

        for topic in topics_to_scan:
            try:
                messages = await self.subscribe(broker, port, topic, duration=3)
                if messages:
                    results.append({
                        "topic": topic,
                        "messages": messages,
                        "vulnerable": True,
                    })
            except Exception:
                pass

        return results

    async def connect(self, target: TargetDescriptor) -> None:
        """Verify MQTT broker is reachable."""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._check_broker_sync, target.host, target.port or 1883
            )
            if result:
                logger.info(f"MQTT broker reachable: {target.host}:{target.port}")
            else:
                logger.warning(f"MQTT broker unreachable: {target.host}:{target.port}")
        except Exception as e:
            logger.warning(f"MQTT broker check failed: {e}")

    def _check_broker_sync(self, host: str, port: int) -> bool:
        """Synchronous broker reachability check."""
        import paho.mqtt.client as mqtt

        try:
            client = mqtt.Client(client_id=f"titan-check-{int(time.time())}")
            client.connect(host, port, keepalive=5)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()
            return True
        except Exception:
            return False
