// zigbee-herdsman (the library Zigbee2MQTT runs on) as the Zigbee host on NetGet's
// co-processor, through its `ember` (EZSP) or `zstack` (Z-Stack MT) adapter on
// tcp://127.0.0.1:<port>.
//
// Starts a Controller (forming or resuming a network to match its configuration), permits
// joining, waits for the device with <ieee> to be interviewed, switches it on, waits for its
// attribute report, and reads onOff back. Each step prints one JSON line; the exit status is 0
// only when every step held.
//
// node herdsman_host.js <herdsman dir> <port> <data dir> <ieee 0x…> <channel> <network key hex> [ember|zstack]
const path = require("node:path");
const fs = require("node:fs");
const [herdsmanDir, port, dataDir, ieee, channel, keyHex, adapterName] = process.argv.slice(2);
const adapter = adapterName || "ember";
const herdsman = require(path.join(herdsmanDir, "node_modules", "zigbee-herdsman"));
const log = (m) => process.stderr.write(`${m}\n`);
herdsman.setLogger({
    debug: () => {},
    info: (m, ns) => log(`INFO ${ns}: ${typeof m === "function" ? m() : m}`),
    warning: (m, ns) => log(`WARN ${ns}: ${typeof m === "function" ? m() : m}`),
    error: (m, ns) => log(`ERROR ${ns}: ${typeof m === "function" ? m() : m}`),
});
const out = (o) => console.log(JSON.stringify(o));
const timeout = (ms, what) => new Promise((_, reject) => setTimeout(() => reject(new Error(`timed out: ${what}`)), ms));

(async () => {
    fs.mkdirSync(dataDir, {recursive: true});
    const controller = new herdsman.Controller({
        network: {
            panID: 0x1a62,
            extendedPanID: [0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd],
            channelList: [Number(channel)],
            networkKey: [...Buffer.from(keyHex, "hex")],
        },
        transport: {path: `tcp://127.0.0.1:${port}`, adapter},
        databasePath: path.join(dataDir, "database.db"),
        databaseBackupPath: path.join(dataDir, "database.db.backup"),
        backupPath: path.join(dataDir, "coordinator_backup.json"),
        adapter: {disableLED: true},
        acceptJoiningDeviceHandler: async () => true,
    });
    let ok = false;
    try {
        const interviewed = new Promise((resolve, reject) => {
            controller.on("deviceInterview", (e) => {
                if (e.device.ieeeAddr !== ieee) return;
                if (e.status === "successful") resolve(e.device);
                else if (e.status === "failed") reject(new Error("interview failed"));
            });
        });
        const reported = new Promise((resolve) => {
            controller.on("message", (m) => {
                if (m.device.ieeeAddr === ieee && m.type === "attributeReport" && m.cluster === "genOnOff") resolve(m.data);
            });
        });
        const started = await controller.start();
        const coordinator = await controller.getCoordinatorVersion();
        out({step: "started", result: started, coordinator});
        await controller.permitJoin(60);
        out({step: "permitted"});
        const device = await Promise.race([interviewed, timeout(45000, "interview")]);
        const ep = device.getEndpoint(1);
        out({
            step: "interviewed", nwk: device.networkAddress, type: device.type, model: device.modelID,
            manufacturer: device.manufacturerName, powerSource: device.powerSource,
            endpoints: device.endpoints.map((e) => e.ID), profile: ep.profileID, deviceId: ep.deviceID,
            inputClusters: ep.inputClusters, outputClusters: ep.outputClusters,
        });
        await ep.command("genOnOff", "on", {});
        out({step: "on"});
        const report = await Promise.race([reported, timeout(15000, "attribute report")]);
        out({step: "reported", data: report});
        const read = await ep.read("genOnOff", ["onOff"]);
        out({step: "read", data: read});
        ok = device.modelID === "Lamp-1" && device.manufacturerName === "NetGet" && report.onOff === 1 && read.onOff === 1;
        out({step: "done", ok});
    } catch (e) {
        out({step: "failed", error: String(e && e.stack || e)});
    } finally {
        try {
            await controller.stop();
        } catch (e) {
            log(`stop: ${e}`);
        }
    }
    process.exit(ok ? 0 : 1);
})();
