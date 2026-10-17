"""Drive a ChirpStack v4 network server through its gRPC API, for NetGet's LoRaWAN gateway test.

    chirpstack_peer.py provision <api> <token> <dev_eui> <app_key> <gateway_eui>
        Creates an application, an EU868 LoRaWAN 1.0.3 OTAA device profile, the device with
        its AppKey, and registers the gateway, in the default tenant. Prints
        {"application_id": ...}.
    chirpstack_peer.py enqueue <api> <token> <dev_eui> <f_port> <hex>
        Queues an unconfirmed downlink. Prints {"id": ...}.

Needs `pip install chirpstack-api grpcio` (the official generated client).
"""

import json
import sys

import grpc
from chirpstack_api import api, common


def channel(addr):
    return grpc.insecure_channel(addr)


def meta(token):
    return [("authorization", "Bearer %s" % token)]


def provision(addr, token, dev_eui, app_key, gateway_eui):
    ch = channel(addr)
    md = meta(token)
    tenants = api.TenantServiceStub(ch).List(api.ListTenantsRequest(limit=10), metadata=md)
    tenant_id = tenants.result[0].id
    app = api.ApplicationServiceStub(ch).Create(
        api.CreateApplicationRequest(
            application=api.Application(name="netget-test", tenant_id=tenant_id)
        ),
        metadata=md,
    )
    profile = api.DeviceProfileServiceStub(ch).Create(
        api.CreateDeviceProfileRequest(
            device_profile=api.DeviceProfile(
                tenant_id=tenant_id,
                name="netget-eu868-1.0.3",
                region=common.Region.EU868,
                mac_version=common.MacVersion.LORAWAN_1_0_3,
                reg_params_revision=common.RegParamsRevision.A,
                adr_algorithm_id="default",
                supports_otaa=True,
                uplink_interval=60,
            )
        ),
        metadata=md,
    )
    devices = api.DeviceServiceStub(ch)
    devices.Create(
        api.CreateDeviceRequest(
            device=api.Device(
                dev_eui=dev_eui,
                name="netget-device",
                application_id=app.id,
                device_profile_id=profile.id,
            )
        ),
        metadata=md,
    )
    # LoRaWAN 1.0.x: ChirpStack keeps the AppKey in nwk_key.
    devices.CreateKeys(
        api.CreateDeviceKeysRequest(
            device_keys=api.DeviceKeys(dev_eui=dev_eui, nwk_key=app_key, app_key=app_key)
        ),
        metadata=md,
    )
    api.GatewayServiceStub(ch).Create(
        api.CreateGatewayRequest(
            gateway=api.Gateway(
                gateway_id=gateway_eui,
                name="netget-gateway",
                tenant_id=tenant_id,
                stats_interval=30,
            )
        ),
        metadata=md,
    )
    print(json.dumps({"application_id": app.id}), flush=True)


def enqueue(addr, token, dev_eui, f_port, data_hex):
    ch = channel(addr)
    r = api.DeviceServiceStub(ch).Enqueue(
        api.EnqueueDeviceQueueItemRequest(
            queue_item=api.DeviceQueueItem(
                dev_eui=dev_eui,
                confirmed=False,
                f_port=int(f_port),
                data=bytes.fromhex(data_hex),
            )
        ),
        metadata=meta(token),
    )
    print(json.dumps({"id": r.id}), flush=True)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "provision":
        provision(*sys.argv[2:7])
    elif cmd == "enqueue":
        enqueue(*sys.argv[2:7])
    else:
        sys.exit("unknown command %s" % cmd)
