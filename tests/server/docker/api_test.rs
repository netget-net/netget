//! Docker Engine API routing and rendering, without a socket.
//!
//! `real_client_test.rs` shows the Docker CLI decodes what these render; this file pins the
//! routing table, the defaults that keep the Go decoder happy, and every refusal.

use netget::server::docker::api::{
    self, parse_version, render_container, render_container_list, render_images, render_info,
    render_networks, render_version, render_volumes, resolve, split_version, EngineIdentity, Route,
};
use serde_json::json;

fn identity() -> EngineIdentity {
    EngineIdentity {
        engine_version: "27.5.1".into(),
        api_version: "1.47".into(),
    }
}

#[test]
fn version_prefixes_are_split_and_validated() {
    assert_eq!(
        split_version("/v1.45/containers/json"),
        (Some("1.45".into()), "/containers/json".into())
    );
    assert_eq!(split_version("/_ping"), (None, "/_ping".into()));
    // A first segment that merely starts with v is a path, not a version.
    assert_eq!(split_version("/volumes"), (None, "/volumes".into()));
    assert_eq!(split_version("/vX.1/info"), (None, "/vX.1/info".into()));
    assert!(
        parse_version("1.47") > parse_version("1.9"),
        "compared numerically"
    );
    assert_eq!(parse_version("1."), None);
}

#[test]
fn the_routing_table() {
    assert_eq!(resolve("HEAD", "/_ping"), Route::Ping);
    assert_eq!(resolve("GET", "/_ping"), Route::Ping);
    assert_eq!(resolve("GET", "/version"), Route::Version);
    assert_eq!(resolve("GET", "/info"), Route::Info);
    assert_eq!(resolve("GET", "/containers/json"), Route::ContainerList);
    assert_eq!(
        resolve("GET", "/containers/web/json"),
        Route::ContainerInspect("web".into())
    );
    assert_eq!(resolve("GET", "/images/json"), Route::ImageList);
    assert_eq!(resolve("GET", "/networks"), Route::NetworkList);
    assert_eq!(resolve("GET", "/volumes"), Route::VolumeList);
    for (m, p) in [
        ("POST", "/containers/create"),
        ("POST", "/containers/web/start"),
        ("POST", "/containers/web/exec"),
        ("POST", "/images/create"),
        ("DELETE", "/containers/web"),
        ("POST", "/_ping"),
    ] {
        assert_eq!(resolve(m, p), Route::Mutating, "{m} {p}");
    }
    assert_eq!(resolve("GET", "/containers/web/logs"), Route::NotFound);
    assert_eq!(resolve("GET", "/images/nginx/json"), Route::NotFound);
    assert_eq!(
        Route::ContainerList.answering_action(),
        Some("send_docker_containers")
    );
    assert_eq!(Route::Ping.resource(), None);
}

#[test]
fn a_minimal_container_gets_every_field_the_decoder_needs() {
    let list = render_container_list(&json!([{"names": ["web"], "image": "nginx"}])).unwrap();
    let c = &list[0];
    assert_eq!(
        c["Names"],
        json!(["/web"]),
        "names are slash-prefixed like the daemon's"
    );
    assert_eq!(c["State"], "running");
    assert_eq!(c["Status"], "Up");
    assert_eq!(
        c["Id"].as_str().unwrap().len(),
        64,
        "an ID is derived from the name"
    );
    assert!(c["ImageID"].as_str().unwrap().starts_with("sha256:"));
    assert!(c["Created"].is_i64());
    assert_eq!(c["Ports"], json!([]));
    assert_eq!(c["HostConfig"]["NetworkMode"], "bridge");
    // The same name derives the same ID in inspect, so `ps` and `inspect` agree.
    let one = render_container(&json!({"names": ["web"], "image": "nginx"})).unwrap();
    assert_eq!(one["Id"], c["Id"]);
    assert_eq!(one["State"]["Running"], true);
    assert_eq!(one["Name"], "/web");
}

#[test]
fn ports_status_and_timestamps_render_as_docker_writes_them() {
    let c = render_container_list(&json!([{
        "names": ["db"], "image": "postgres:16", "state": "exited", "exit_code": 3,
        "created": "2026-09-01T10:00:00Z",
        "ports": [{"private_port": 5432, "public_port": 15432, "type": "tcp"},
                  {"private_port": 53, "type": "udp"}]
    }]))
    .unwrap();
    assert_eq!(c[0]["Status"], "Exited (3)");
    assert_eq!(c[0]["Created"], 1788256800);
    assert_eq!(
        c[0]["Ports"],
        json!([
            {"PrivatePort": 5432, "Type": "tcp", "PublicPort": 15432, "IP": "0.0.0.0"},
            {"PrivatePort": 53, "Type": "udp"}
        ])
    );
    let one = render_container(&json!({
        "names": ["db"], "image": "postgres:16", "state": "exited",
        "ports": [{"private_port": 5432, "public_port": 15432}]
    }))
    .unwrap();
    assert_eq!(
        one["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"],
        "15432"
    );
    assert_eq!(one["State"]["Running"], false);
}

/// What llama3.1:8b actually wrote for "a container named eval-web" and "a stopped container
/// that exited with code 0" in the eval. Every one of these was refused, so `docker ps` printed
/// an error for a request the model had understood.
#[test]
fn a_name_for_an_id_a_stopped_state_and_a_codeless_exit_status_render_as_docker_writes_them() {
    // The name written as the ID: rendered with the ID derived from that name — letters and
    // digits only, and the same one `ps` and `inspect` derive when the ID is left out.
    let named = render_container_list(&json!([{
        "id": "eval-web", "names": ["eval-web"], "image": "nginx:1.27"
    }]))
    .unwrap();
    let omitted =
        render_container_list(&json!([{"names": ["eval-web"], "image": "nginx:1.27"}])).unwrap();
    let id = named[0]["Id"].as_str().unwrap();
    assert_eq!(id.len(), 64, "{id}");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
    assert_eq!(named[0]["Id"], omitted[0]["Id"]);
    let inspected = render_container(&json!({
        "id": "eval-web", "names": ["eval-web"], "image": "nginx:1.27"
    }))
    .unwrap();
    assert_eq!(inspected["Id"], named[0]["Id"]);
    // Letters and digits are still used exactly as given.
    let given =
        render_container_list(&json!([{"id": "abc123", "names": ["w"], "image": "x"}])).unwrap();
    assert_eq!(given[0]["Id"], "abc123");
    // An image ID written the same way.
    let img = render_images(&json!([{"id": "my-image", "repo_tags": ["api:2"]}])).unwrap();
    let img_id = img[0]["Id"].as_str().unwrap();
    assert!(
        img_id.starts_with("sha256:") && img_id.len() == 71,
        "{img_id}"
    );

    // "stopped" is the word for what Docker calls exited.
    let stopped = render_container_list(&json!([{
        "names": ["eval-migrate"], "image": "api:2", "state": "stopped", "exit_code": 0
    }]))
    .unwrap();
    assert_eq!(stopped[0]["State"], "exited");
    assert_eq!(stopped[0]["Status"], "Exited (0)");

    // An exited container's status always carries its code, in the daemon's form.
    for (given, expected) in [
        ("Exited 10 minutes ago", "Exited (0) 10 minutes ago"),
        ("Stopped", "Exited (0)"),
        ("Exited (0) 3 hours ago", "Exited (0) 3 hours ago"),
    ] {
        let c = render_container_list(&json!([{
            "names": ["m"], "image": "api:2", "state": "exited", "exit_code": 0, "status": given
        }]))
        .unwrap();
        assert_eq!(c[0]["Status"], expected, "{given}");
    }
    // A running container's wording is the model's own.
    let up = render_container_list(&json!([{
        "names": ["w"], "image": "x", "state": "running", "status": "Up 2 hours"
    }]))
    .unwrap();
    assert_eq!(up[0]["Status"], "Up 2 hours");
}

/// `answer_with` names the action for the route, and for an inspect the 404 with Docker's
/// own message — the one thing the eval's missing-container case needed and the model missed.
#[test]
fn every_modelled_route_names_its_answer() {
    let none = json!({});
    assert_eq!(
        Route::Version.answer_with(&none).as_deref(),
        Some("send_docker_version")
    );
    let inspect = Route::ContainerInspect("eval-ghost".into())
        .answer_with(&none)
        .unwrap();
    assert!(inspect.starts_with("send_docker_container "), "{inspect}");
    assert!(
        inspect.contains("send_docker_error with status 404")
            && inspect.contains("No such container: eval-ghost"),
        "{inspect}"
    );
    let running = Route::ContainerList.answer_with(&none).unwrap();
    let all = Route::ContainerList
        .answer_with(&json!({"all": "1"}))
        .unwrap();
    // A list route names the array, not just the action: told only the action, the model
    // sent it empty.
    assert!(
        running.contains("containers array") && running.contains("the running containers"),
        "{running}"
    );
    assert!(
        all.contains("containers array") && all.contains("running or not"),
        "{all}"
    );
    assert_eq!(
        Route::Info.answer_with(&none).as_deref(),
        Some("send_docker_info")
    );
    for (route, array) in [
        (Route::ImageList, "images array"),
        (Route::NetworkList, "networks array"),
        (Route::VolumeList, "volumes array"),
    ] {
        let hint = route.answer_with(&none).unwrap();
        assert!(
            hint.starts_with(route.answering_action().unwrap()) && hint.contains(array),
            "{hint}"
        );
    }
    for route in [Route::Ping, Route::Mutating, Route::NotFound] {
        assert_eq!(route.answer_with(&none), None);
    }
}

#[test]
fn every_malformed_answer_is_refused_with_a_reason() {
    let cases = [
        (json!([{"image": "nginx"}]), "needs a name"),
        (json!([{"names": ["-bad"], "image": "nginx"}]), "must match"),
        (json!([{"names": ["web"]}]), "needs an image"),
        (
            json!([{"names": ["web"], "image": "nginx", "state": "sleeping"}]),
            "is not one of",
        ),
        (
            json!([{"names": ["web"], "image": "nginx", "ports": [{"private_port": 70000}]}]),
            "is not a port",
        ),
        (
            json!([{"names": ["web"], "image": "nginx", "ports": [{"private_port": 80, "type": "icmp"}]}]),
            "tcp, udp or sctp",
        ),
        (
            json!([{"names": ["web"], "image": "nginx", "id": "not hex!"}]),
            "letters and digits",
        ),
        (
            json!([{"names": ["web"], "image": "nginx", "created": "yesterday"}]),
            "RFC 3339",
        ),
        (json!({"names": ["web"]}), "must be an array"),
    ];
    for (value, needle) in cases {
        let reason = render_container_list(&value).expect_err(&value.to_string());
        assert!(
            reason.contains(needle),
            "{value}: expected {needle:?} in {reason}"
        );
    }
    assert!(render_images(&json!([{"repo_tags": ["has space:1"]}])).is_err());
    assert!(render_networks(&json!([{"driver": "bridge"}])).is_err());
    assert!(render_volumes(&json!([{"name": "/abs"}])).is_err());
    assert!(render_version(&json!({"api_version": "latest"}), &identity()).is_err());
    assert!(render_info(&json!({"images": -1}), &identity()).is_err());
}

#[test]
fn version_and_info_default_everything_the_model_left_out() {
    let v = render_version(&json!({}), &identity()).unwrap();
    assert_eq!(v["Version"], "27.5.1");
    assert_eq!(v["ApiVersion"], "1.47");
    assert_eq!(v["MinAPIVersion"], api::MIN_API_VERSION);
    assert_eq!(v["Components"][0]["Name"], "Engine");
    let i = render_info(
        &json!({"containers_running": 2, "containers_stopped": 1}),
        &identity(),
    )
    .unwrap();
    assert_eq!(
        i["Containers"], 3,
        "the total defaults to the sum of the states"
    );
    assert_eq!(i["ServerVersion"], "27.5.1");
    assert_eq!(i["Swarm"]["LocalNodeState"], "inactive");
    let images = render_images(&json!([{"repo_tags": ["nginx:1.27"]}])).unwrap();
    assert_eq!(images[0]["SharedSize"], -1);
    assert!(images[0]["Id"].as_str().unwrap().starts_with("sha256:"));
    let vols = render_volumes(&json!([])).unwrap();
    assert_eq!(vols, json!({"Volumes": [], "Warnings": []}));
}

/// A model that copies one ID onto every container (the action example's, in the eval) gets
/// distinct IDs: the first keeps it, each repeat gets the one derived from its name.
#[test]
fn a_repeated_container_id_is_replaced_by_the_name_derived_one() {
    let copied = "3f4e1a2b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f";
    let rendered = render_container_list(&json!([
        {"id": copied, "names": ["eval-api"], "image": "api:2", "state": "running"},
        {"id": copied, "names": ["eval-migrate"], "image": "api:2", "state": "exited"}
    ]))
    .expect("both containers render");
    let first = rendered[0]["Id"].as_str().unwrap();
    let second = rendered[1]["Id"].as_str().unwrap();
    assert_eq!(first, copied, "the first keeps the ID it was given");
    assert_eq!(second, api::derived_id("container:eval-migrate"));
    assert_ne!(first[..12], second[..12]);

    // Distinct IDs are left alone.
    let distinct = render_container_list(&json!([
        {"id": "aaaaaaaaaaaa", "names": ["a"], "image": "x", "state": "running"},
        {"id": "bbbbbbbbbbbb", "names": ["b"], "image": "x", "state": "running"}
    ]))
    .unwrap();
    assert_eq!(distinct[1]["Id"], "bbbbbbbbbbbb");
}

/// Each route is raised as `docker_api_request` offering only the action that answers it and
/// `send_docker_error`: offered all eight, llama3.1:8b answered an inspect of a missing
/// container with `send_docker_volumes` in every run. The id is the declared one, so handlers
/// keep matching, and the declared event keeps every action for documentation.
#[test]
fn every_route_offers_only_its_own_answer_and_the_error() {
    use netget::server::docker::actions::{event_for_resource, DOCKER_API_REQUEST_EVENT};
    let routes = [
        Route::Version,
        Route::Info,
        Route::ContainerList,
        Route::ContainerInspect("web".into()),
        Route::ImageList,
        Route::NetworkList,
        Route::VolumeList,
    ];
    for route in routes {
        let resource = route
            .resource()
            .expect("a model-answered route has a resource");
        let event = event_for_resource(resource);
        assert_eq!(event.id, "docker_api_request", "{resource}");
        let names: Vec<&str> = event.actions.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(
            names,
            vec![route.answering_action().unwrap(), "send_docker_error"],
            "{resource}"
        );
        // A subset of what the declared event documents, never an action of its own.
        for action in &event.actions {
            assert!(
                DOCKER_API_REQUEST_EVENT
                    .actions
                    .iter()
                    .any(|a| a.name == action.name),
                "{resource}: {} is not declared",
                action.name
            );
        }
    }
    assert!(event_for_resource("container")
        .description
        .contains("status 404 when there is no such container"));
    // Anything else is the declared event with every action.
    assert_eq!(event_for_resource("unknown").actions.len(), 8);
}
