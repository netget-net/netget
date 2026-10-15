#[cfg(all(unix, feature = "libpcap"))]
use netget::server::datalink::DataLinkServer;

#[test]
#[cfg(all(unix, feature = "libpcap"))]
fn test_list_devices() {
    // This should work on any system with pcap installed
    let devices = DataLinkServer::list_devices();
    match devices {
        Ok(devs) => {
            println!("Found {} network devices", devs.len());
            for dev in devs {
                println!("  - {}: {:?}", dev.name, dev.desc);
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not list devices: {}", e);
            eprintln!("This may be due to permissions or pcap not being installed");
        }
    }
}
