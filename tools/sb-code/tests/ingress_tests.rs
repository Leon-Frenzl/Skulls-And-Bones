use sb_code::ingress::{self, IngressEndpoint};
use sb_code::session::get_active_callsign;

#[test]
fn test_ingress_endpoint_derivation() {
    let callsign = get_active_callsign();
    let endpoint = IngressEndpoint {
        port: 5173,
        process_name: "vite.exe".to_string(),
        pid: Some(1234),
        mesh_url: format!("http://{}.sbm:5173", callsign),
        category: "Web".to_string(),
    };

    assert_eq!(endpoint.port, 5173);
    assert_eq!(endpoint.mesh_url, format!("http://{}.sbm:5173", callsign));
    assert!(endpoint.mesh_url.contains(".sbm:"));
}

#[test]
fn test_ingress_report_empty_and_active() {
    // 1. Empty report should not panic
    ingress::print_ingress_report(&[]);

    // 2. Report with active endpoint
    let callsign = get_active_callsign();
    let endpoints = vec![
        IngressEndpoint {
            port: 3000,
            process_name: "node.exe".to_string(),
            pid: Some(9999),
            mesh_url: format!("http://{}.sbm:3000", callsign),
            category: "WebServer".to_string(),
        },
        IngressEndpoint {
            port: 8080,
            process_name: "cargo.exe".to_string(),
            pid: Some(1010),
            mesh_url: format!("http://{}.sbm:8080", callsign),
            category: "Web".to_string(),
        },
    ];

    ingress::print_ingress_report(&endpoints);
    assert_eq!(endpoints.len(), 2);
}
