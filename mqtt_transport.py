import json

import paho.mqtt.publish as publish

from config import (
    MQTT_BROKER,
    MQTT_PORT,
    MQTT_TOPIC,
    MQTT_CA,
    MQTT_CERT,
    MQTT_KEY,
)


def publish_event(event):
    payload = json.dumps(
        event,
        ensure_ascii=False
    )

    publish.single(
        MQTT_TOPIC,
        payload=payload,
        qos=1,
        hostname=MQTT_BROKER,
        port=MQTT_PORT,
        client_id="sensor-01",
        tls={
            "ca_certs": str(MQTT_CA),
            "certfile": str(MQTT_CERT),
            "keyfile": str(MQTT_KEY),
        },
    )
