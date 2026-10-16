//! A minimal GSDML (PROFINET's device description, an XML file an engineering tool imports)
//! for a device layout, so a controller configured from GSDML can talk to the device NetGet
//! describes.
//!
//! It carries what a controller needs to build a Connect — the identity, the access point and
//! its interface/port submodules, every module with its submodules and their cyclic data — and
//! nothing else: no parameters, diagnosis texts, graphics or timing beyond a 1 ms minimum
//! device interval. Pure function; nothing is written anywhere.
use super::dcp::Identity;
use super::values::{FieldType, SubmoduleSpec};
use std::fmt::Write as _;

fn esc(s: &str) -> String {
    crate::utils::sanitize::line_field(s)
        .chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn data_type(t: FieldType) -> &'static str {
    match t {
        FieldType::Bool => "Boolean",
        FieldType::U8 => "Unsigned8",
        FieldType::I8 => "Integer8",
        FieldType::U16 => "Unsigned16",
        FieldType::I16 => "Integer16",
        FieldType::U32 => "Unsigned32",
        FieldType::I32 => "Integer32",
        FieldType::F32 => "Float32",
    }
}

fn io_data(out: &mut String, s: &SubmoduleSpec, texts: &mut Vec<(String, String)>) {
    if s.inputs.is_empty() && s.outputs.is_empty() {
        out.push_str("<IOData/>");
        return;
    }
    out.push_str("<IOData>");
    for (tag, fields) in [("Input", &s.inputs), ("Output", &s.outputs)] {
        if fields.is_empty() {
            continue;
        }
        let _ = write!(out, "<{tag}>");
        for f in fields.iter() {
            let id = format!("T_{}_{}_{}_{}", s.slot, s.subslot, tag, f.name);
            let _ = write!(
                out,
                "<DataItem DataType=\"{}\" TextId=\"{}\"/>",
                data_type(f.ty),
                esc(&id)
            );
            texts.push((id, f.name.clone()));
        }
        let _ = write!(out, "</{tag}>");
    }
    out.push_str("</IOData>");
}

/// Render the GSDML for `identity` and `layout`. Slot 0 is the device access point; its
/// subslots 0x8000 and above become the interface and port submodules.
pub fn render(identity: &Identity, layout: &[SubmoduleSpec]) -> String {
    let mut texts: Vec<(String, String)> = Vec::new();
    let dap_ident = layout
        .iter()
        .find(|s| s.slot == 0)
        .map(|s| s.module_ident)
        .unwrap_or(1);
    let mut x = String::new();
    x.push_str("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
    x.push_str(
        "<ISO15745Profile xmlns=\"http://www.profibus.com/GSDML/2003/11/DeviceProfile\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n",
    );
    x.push_str(
        "<ProfileHeader><ProfileIdentification>PROFINET Device Profile</ProfileIdentification>\
         <ProfileRevision>1.00</ProfileRevision><ProfileName>Device Profile for PROFINET \
         Devices</ProfileName><ProfileSource>PROFIBUS Nutzerorganisation e. V. (PNO)\
         </ProfileSource><ProfileClassID>Device</ProfileClassID><ISO15745Reference>\
         <ISO15745Part>4</ISO15745Part><ISO15745Edition>1</ISO15745Edition>\
         <ProfileTechnology>GSDML</ProfileTechnology></ISO15745Reference></ProfileHeader>\n",
    );
    x.push_str("<ProfileBody>\n");
    let _ = writeln!(
        x,
        "<DeviceIdentity VendorID=\"{:#06x}\" DeviceID=\"{:#06x}\"><InfoText TextId=\"T_INFO\"/>\
         <VendorName Value=\"NetGet\"/></DeviceIdentity>",
        identity.vendor_id, identity.device_id
    );
    texts.push(("T_INFO".into(), identity.type_of_station.clone()));
    x.push_str(
        "<DeviceFunction><Family MainFamily=\"I/O\" ProductFamily=\"NetGet\"/></DeviceFunction>\n",
    );
    x.push_str("<ApplicationProcess>\n<DeviceAccessPointList>\n");
    let _ = write!(
        x,
        "<DeviceAccessPointItem ID=\"DAP\" PhysicalSlots=\"0..{}\" ModuleIdentNumber=\"{:#010x}\" \
         MinDeviceInterval=\"32\" ImplementationType=\"NetGet\" DNS_CompatibleName=\"{}\" \
         FixedInSlots=\"0\" ObjectUUID_LocalIndex=\"1\" RequiredSchemaVersion=\"V2.4\">\
         <ModuleInfo><Name TextId=\"T_INFO\"/><InfoText TextId=\"T_INFO\"/></ModuleInfo>",
        layout.iter().map(|s| s.slot).max().unwrap_or(0),
        dap_ident,
        esc(&identity.name_of_station)
    );
    x.push_str("<VirtualSubmoduleList>");
    for s in layout.iter().filter(|s| s.slot == 0 && s.subslot < 0x8000) {
        let _ = write!(
            x,
            "<VirtualSubmoduleItem ID=\"S_0_{}\" SubmoduleIdentNumber=\"{:#010x}\" \
             FixedInSubslots=\"{}\">",
            s.subslot, s.submodule_ident, s.subslot
        );
        io_data(&mut x, s, &mut texts);
        x.push_str("<ModuleInfo><Name TextId=\"T_INFO\"/></ModuleInfo></VirtualSubmoduleItem>");
    }
    x.push_str("</VirtualSubmoduleList>");
    let system: Vec<&SubmoduleSpec> = layout
        .iter()
        .filter(|s| s.slot == 0 && s.subslot >= 0x8000)
        .collect();
    if !system.is_empty() {
        x.push_str("<SystemDefinedSubmoduleList>");
        for s in system {
            let tag = if s.subslot & 0x00ff == 0 {
                "InterfaceSubmoduleItem"
            } else {
                "PortSubmoduleItem"
            };
            let _ = write!(
                x,
                "<{tag} ID=\"S_0_{}\" SubslotNumber=\"{}\" SubmoduleIdentNumber=\"{:#010x}\" \
                 TextId=\"T_INFO\"/>",
                s.subslot, s.subslot, s.submodule_ident
            );
        }
        x.push_str("</SystemDefinedSubmoduleList>");
    }
    let mut slots: Vec<u16> = layout
        .iter()
        .filter(|s| s.slot != 0)
        .map(|s| s.slot)
        .collect();
    slots.sort();
    slots.dedup();
    x.push_str("<UseableModules>");
    for slot in &slots {
        let _ = write!(
            x,
            "<ModuleItemRef ModuleItemTarget=\"M_{slot}\" FixedInSlots=\"{slot}\" \
             AllowedInSlots=\"{slot}\"/>"
        );
    }
    x.push_str("</UseableModules></DeviceAccessPointItem>\n</DeviceAccessPointList>\n");
    x.push_str("<ModuleList>\n");
    for slot in &slots {
        let subs: Vec<&SubmoduleSpec> = layout.iter().filter(|s| s.slot == *slot).collect();
        let _ = write!(
            x,
            "<ModuleItem ID=\"M_{slot}\" ModuleIdentNumber=\"{:#010x}\"><ModuleInfo><Name \
             TextId=\"T_INFO\"/></ModuleInfo><UseableSubmodules>",
            subs[0].module_ident
        );
        for s in &subs {
            let _ = write!(
                x,
                "<SubmoduleItemRef SubmoduleItemTarget=\"S_{}_{}\" FixedInSubslots=\"{}\" \
                 AllowedInSubslots=\"{}\"/>",
                s.slot, s.subslot, s.subslot, s.subslot
            );
        }
        x.push_str("</UseableSubmodules></ModuleItem>\n");
    }
    x.push_str("</ModuleList>\n<SubmoduleList>\n");
    for s in layout.iter().filter(|s| s.slot != 0) {
        let _ = write!(
            x,
            "<SubmoduleItem ID=\"S_{}_{}\" SubmoduleIdentNumber=\"{:#010x}\" API=\"{}\">",
            s.slot, s.subslot, s.submodule_ident, s.api
        );
        io_data(&mut x, s, &mut texts);
        x.push_str("<ModuleInfo><Name TextId=\"T_INFO\"/></ModuleInfo></SubmoduleItem>\n");
    }
    x.push_str("</SubmoduleList>\n");
    x.push_str("<ExternalTextList><PrimaryLanguage>");
    for (id, text) in &texts {
        let _ = write!(x, "<Text TextId=\"{}\" Value=\"{}\"/>", esc(id), esc(text));
    }
    x.push_str("</PrimaryLanguage></ExternalTextList>\n");
    x.push_str("</ApplicationProcess>\n</ProfileBody>\n</ISO15745Profile>\n");
    x
}
