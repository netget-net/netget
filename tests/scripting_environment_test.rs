use netget::scripting::environment::ScriptingEnvironment;

#[test]
fn test_environment_detection() {
    let env = ScriptingEnvironment::detect();
    // At least one should be available on most systems
    // (but we don't fail if neither is available)
    println!("Detected environments: {:?}", env);
}

#[test]
fn test_format_available() {
    let env = ScriptingEnvironment {
        python: Some("Python 3.11.0".to_string()),
        javascript: Some("v20.0.0".to_string()),
        go: Some("go version go1.21.0".to_string()),
        perl: Some("perl 5.34.0".to_string()),
    };
    let formatted = env.format_available();
    assert!(formatted.contains("Python"));
    assert!(formatted.contains("Node.js"));
    assert!(formatted.contains("Go"));
}

#[test]
fn test_format_available_none() {
    let env = ScriptingEnvironment {
        python: None,
        javascript: None,
        go: None,
        perl: None,
    };
    assert_eq!(env.format_available(), "None");
}

/// `perl --version` is a blank line and a copyright notice, which used to reach the startup
/// log and every prompt listing the runtimes.
#[test]
fn perl_is_reported_by_its_version_alone() {
    let env = ScriptingEnvironment::detect();
    if let Some(perl) = env.perl {
        assert!(
            !perl.contains('\n') && !perl.contains("Larry Wall"),
            "one line, no copyright notice: {perl:?}"
        );
    }
}
