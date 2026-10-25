-- Prosody for the integration test (integration_test.go): plaintext sign-in, no TLS.
admins = {}
plugin_paths = {}

modules_enabled = {
    "roster"; "saslauth"; "disco"; "ping"; "offline"; "cloud_notify";
}

c2s_require_encryption = false
allow_unencrypted_plain_auth = true
authentication = "internal_plain"
storage = "internal"
log = { debug = "*console" }

component_ports = { 5347 }
component_interfaces = { "0.0.0.0" }

VirtualHost "localhost"

Component "push.localhost"
    component_secret = "relay"
