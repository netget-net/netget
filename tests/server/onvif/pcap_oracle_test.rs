//! The ONVIF device's PTZ, Events, Media2, Imaging and Device Set* exchanges read by an
//! independent dissector: each request and the device's answer, as they crossed one TCP stream,
//! handed to tshark's HTTP and XML dissectors (`helpers::pcap_oracle`). The oracle fails on any
//! Expert Info at Warn or above and on HTTP not being recognised; then the SOAP body element
//! tshark read in each direction (`xml.tag`, its first element after the Envelope, Header and
//! Body) must be the operation and its response — what tshark read, not what NetGet wrote. The
//! fields used, `http.request.uri`, `http.response.code` and `xml.tag`, are in tshark 4.2.
//! The model is `real_client_test::POLICY`; no LLM calls.
use super::real_client_test::{policy, start};
use crate::helpers::pcap_oracle::PcapOracle;
use netget::llm::actions::protocol_trait::Server;
use netget::server::onvif::actions::OnvifProtocol;
use netget::server::onvif::wire;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One HTTP POST on its own connection: the bytes sent and the bytes answered.
async fn exchange(port: u16, path: &str, body: &str) -> (Vec<u8>, Vec<u8>) {
    let envelope = wire::request_envelope(None, body);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{envelope}",
        envelope.len()
    )
    .into_bytes();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut response))
        .await
        .expect("the device did not answer")
        .unwrap();
    (request, response)
}

/// The SOAP body elements tshark read, per packet direction: the first `xml.tag` after
/// `<…:Body>` in each packet that carried XML.
fn body_tags(rows: &[Vec<String>]) -> Vec<String> {
    rows.iter()
        .filter_map(|r| r.get(2))
        .filter(|tags| !tags.is_empty())
        .filter_map(|tags| {
            let tags: Vec<&str> = tags.split(',').collect();
            let body = tags.iter().position(|t| t.contains(":Body>"))?;
            tags.get(body + 1).map(|t| t.to_string())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tshark_reads_every_new_service_both_ways() {
    let (state, id, port) = start(policy(), json!({})).await;
    let pull_point = {
        let (_, answer) = exchange(
            port,
            wire::EVENTS_PATH,
            "<tev:CreatePullPointSubscription><tev:InitialTerminationTime>PT60S</tev:InitialTerminationTime></tev:CreatePullPointSubscription>",
        )
        .await;
        let text = String::from_utf8_lossy(&answer).to_string();
        let start = text
            .find(wire::SUBSCRIPTION_PREFIX)
            .unwrap_or_else(|| panic!("{text}"));
        let end = text[start..].find('<').unwrap() + start;
        text[start..end].to_string()
    };
    OnvifProtocol
        .execute_action_with_state(
            json!({"type": "onvif_raise_event", "topic": "tns1:Device/Trigger/DigitalInput",
                   "source": {"InputToken": "door"}, "data": {"LogicalState": false}}),
            state.clone(),
            Some(id),
        )
        .await
        .unwrap();
    let cases: Vec<(&str, String, &str, &str)> = vec![
        (
            wire::EVENTS_PATH,
            "<tev:CreatePullPointSubscription><tev:Filter><wsnt:TopicExpression Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet\">tns1:VideoSource//.</wsnt:TopicExpression></tev:Filter></tev:CreatePullPointSubscription>".into(),
            "<tev:CreatePullPointSubscription>",
            "<tev:CreatePullPointSubscriptionResponse>",
        ),
        (
            &pull_point,
            "<tev:PullMessages><tev:Timeout>PT1S</tev:Timeout><tev:MessageLimit>10</tev:MessageLimit></tev:PullMessages>".into(),
            "<tev:PullMessages>",
            "<tev:PullMessagesResponse>",
        ),
        (
            &pull_point,
            "<wsnt:Renew><wsnt:TerminationTime>PT120S</wsnt:TerminationTime></wsnt:Renew>".into(),
            "<wsnt:Renew>",
            "<wsnt:RenewResponse>",
        ),
        (
            wire::EVENTS_PATH,
            "<tev:GetEventProperties/>".into(),
            "<tev:GetEventProperties/>",
            "<tev:GetEventPropertiesResponse>",
        ),
        (
            wire::PTZ_PATH,
            "<tptz:ContinuousMove><tptz:ProfileToken>main</tptz:ProfileToken><tptz:Velocity><tt:PanTilt x=\"0.5\" y=\"0\"/></tptz:Velocity></tptz:ContinuousMove>".into(),
            "<tptz:ContinuousMove>",
            "<tptz:ContinuousMoveResponse/>",
        ),
        (
            wire::PTZ_PATH,
            "<tptz:GetStatus><tptz:ProfileToken>main</tptz:ProfileToken></tptz:GetStatus>".into(),
            "<tptz:GetStatus>",
            "<tptz:GetStatusResponse>",
        ),
        (
            wire::PTZ_PATH,
            "<tptz:SetPreset><tptz:ProfileToken>main</tptz:ProfileToken><tptz:PresetName>Door</tptz:PresetName></tptz:SetPreset>".into(),
            "<tptz:SetPreset>",
            "<tptz:SetPresetResponse>",
        ),
        (
            wire::MEDIA2_PATH,
            "<tr2:GetProfiles><tr2:Type>All</tr2:Type></tr2:GetProfiles>".into(),
            "<tr2:GetProfiles>",
            "<tr2:GetProfilesResponse>",
        ),
        (
            wire::IMAGING_PATH,
            "<timg:GetImagingSettings><timg:VideoSourceToken>lobby_cam</timg:VideoSourceToken></timg:GetImagingSettings>".into(),
            "<timg:GetImagingSettings>",
            "<timg:GetImagingSettingsResponse>",
        ),
        (
            wire::DEVICE_PATH,
            "<tds:SetHostname><tds:Name>lobby-cam-3</tds:Name></tds:SetHostname>".into(),
            "<tds:SetHostname>",
            "<tds:SetHostnameResponse/>",
        ),
    ];
    for (path, body, request_tag, response_tag) in cases {
        let (request, response) = exchange(port, path, &body).await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{request_tag}: {text}");
        let oracle = || {
            PcapOracle::tcp("onvif")
                .to_server(&request)
                .from_server(&response)
        };
        oracle().assert_clean();
        let rows = oracle()
            .fields(&["http.request.uri", "http.response.code", "xml.tag"])
            .unwrap();
        // tshark repeats the request's URI on its response; the request is the row without a
        // status code.
        let uris: Vec<&str> = rows
            .iter()
            .filter(|r| r.get(1).is_none_or(|c| c.is_empty()))
            .filter_map(|r| r.first().map(String::as_str))
            .filter(|u| !u.is_empty())
            .collect();
        assert_eq!(uris, vec![path], "{rows:?}");
        assert!(
            rows.iter().any(|r| r.get(1).is_some_and(|c| c == "200")),
            "{rows:?}"
        );
        assert_eq!(
            body_tags(&rows),
            vec![request_tag.to_string(), response_tag.to_string()],
            "tshark read {rows:?}"
        );
        // The pulled notification, as tshark read it.
        if request_tag == "<tev:PullMessages>" {
            let tags = rows
                .iter()
                .filter_map(|r| r.get(2))
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            assert!(tags.contains("<wsnt:NotificationMessage>"), "{tags}");
            assert!(
                tags.contains("<tt:SimpleItem Name=\"LogicalState\" Value=\"false\"/>"),
                "{tags}"
            );
        }
    }
}
