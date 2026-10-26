"""Basic Notification through python onvif-zeep-async's NotificationManager, as Home Assistant
uses it for its webhook: the script runs the consumer itself (an aiohttp server on a loopback
port it binds), creates the manager — which Subscribes that address — prints
`{"step": "subscribed"}`, and reads every Notify the device POSTs with the manager's own
`process()` until one carries the DigitalInput the test raises (or 30 s pass). Then Renew,
the manager's shutdown (Unsubscribe), a Renew of the ended subscription, and Subscribes naming a
consumer outside the device's allowlist and an https one, each refused.

Prints one JSON object as its last line. Usage: python zeep_notify.py host port username password
"""
import asyncio
import datetime as dt
import json
import sys

import onvif
import zeep.exceptions
from aiohttp import web


def fault(err):
    return {"fault": str(err.message), "subcodes": [q.localname for q in (err.subcodes or [])]}


def emit(obj):
    print(json.dumps(obj, default=str), flush=True)


def messages(result):
    out = []
    for n in (result.NotificationMessage or []) if result is not None else []:
        msg = n.Message._value_1
        items = lambda part: {i.Name: i.Value for i in (part.SimpleItem if part is not None else [])}
        out.append({
            "topic": n.Topic._value_1.strip(),
            "subscription": n.SubscriptionReference.Address._value_1 if n.SubscriptionReference else None,
            "utc_time": msg.UtcTime.isoformat() if msg.UtcTime is not None else None,
            "property_operation": str(msg.PropertyOperation) if msg.PropertyOperation else None,
            "source": items(msg.Source),
            "data": items(msg.Data),
        })
    return out


async def main(host, port, user, password):
    out = {"notifies": []}
    manager = None
    seen = asyncio.Event()

    async def consume(request):
        body = await request.read()
        entry = {"path": request.path, "content_type": request.headers.get("Content-Type")}
        try:
            entry["messages"] = messages(manager.process(body)) if manager else []
        except Exception as e:  # what the library could not read is reported, not hidden
            entry["process_error"] = repr(e)
        out["notifies"].append(entry)
        if any(m["topic"].endswith("DigitalInput") for m in entry.get("messages", [])):
            seen.set()
        return web.Response(status=200)

    app = web.Application()
    app.router.add_post("/zeep-consumer", consume)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    consumer_port = site._server.sockets[0].getsockname()[1]
    consumer = f"http://127.0.0.1:{consumer_port}/zeep-consumer"
    out["consumer"] = consumer

    cam = onvif.ONVIFCamera(host, int(port), user, password, adjust_time=True)
    await cam.update_xaddrs()
    try:
        manager = await cam.create_notification_manager(consumer, dt.timedelta(seconds=120), lambda: None)
    except zeep.exceptions.Fault as err:
        out["subscribe"] = fault(err)
        emit(out)
        return
    out["subscription_address"] = cam.xaddrs.get("http://www.onvif.org/ver10/events/wsdl/NotificationConsumer")
    emit({"step": "subscribed"})
    try:
        await asyncio.wait_for(seen.wait(), 30)
    except asyncio.TimeoutError:
        out["timed_out"] = True

    subscription = await cam.create_subscription_service("NotificationConsumer")
    try:
        r = await subscription.Renew(cam.get_next_termination_time(dt.timedelta(seconds=300)))
        out["renew"] = {"current": str(r.CurrentTime), "termination": str(r.TerminationTime)}
    except zeep.exceptions.Fault as err:
        out["renew"] = fault(err)
    await manager.shutdown()
    try:
        await subscription.Renew(cam.get_next_termination_time(dt.timedelta(seconds=300)))
        out["renew_after_unsubscribe"] = "renewed"
    except zeep.exceptions.Fault as err:
        out["renew_after_unsubscribe"] = fault(err)

    notification = await cam.create_notification_service()
    for name, address in (("subscribe_outside_allowlist", "http://192.0.2.1:9/zeep-consumer"),
                          ("subscribe_https", f"https://127.0.0.1:{consumer_port}/zeep-consumer")):
        try:
            await notification.Subscribe({"ConsumerReference": {"Address": address}, "InitialTerminationTime": "PT60S"})
            out[name] = "subscribed"
        except zeep.exceptions.Fault as err:
            out[name] = fault(err)
    await cam.close()
    await runner.cleanup()
    emit(out)


asyncio.run(main(*sys.argv[1:5]))
