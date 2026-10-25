# yapnest-relay

Yapnest's push relay: the XEP-0357 app server that wakes the iOS app when a message arrives. It connects to an
XMPP server as an external component (XEP-0114) and serves a domain, say `push.yapnest.fr`. Every user's server
reaches it over s2s, whichever server they're on. Its source is at <https://github.com/ShimmerGlass/yapnest-relay>.

1. **Register:** the app runs the `register-push-apns` ad-hoc command (XEP-0050) on the relay, with its APNs
   device token. It gets a **node** back.
2. **Enable:** the app enables push on its own server (`<enable xmlns='urn:xmpp:push:0' jid='push.yapnest.fr'
   node='…'/>`).
3. **Publish:** when a message arrives while the app is away, the user's server publishes to that node. The relay
   sends Apple a content-free alert with `mutable-content`. That wakes the app's notification service extension,
   which fetches the message, decrypts it and shows it.

Nothing about a message reaches Apple. The summary some servers include (sender, body) is dropped.

## Nodes

The relay keeps no state. A node is the registration sealed with `RELAY_KEY` (AES-GCM): the device token, the
environment (sandbox or production) and the bare JID that registered it.

- **The user's server never sees the device token.**
- **Only the registering account's server can use a node.** Prosody publishes as the user and ejabberd as the
  server, so either is accepted.
- **Sealing is deterministic.** A device that registers again gets the same node, so its server replaces the
  target instead of piling up duplicates.
- **Dead tokens are dropped.** When Apple says a token is gone (the app was removed), the relay answers the
  publish with `item-not-found` and the server drops the target.

## Bursts

Servers publish for more than messages: ejabberd's default (`notify_on: all`) pushes for presence and PEP
events too. Each push wakes the app's extension, which catches up on everything, so the relay sends at most one
push per device every 10 seconds. A publish inside that window gets one trailing push at its end, so the last
message of a burst still wakes the app. On ejabberd, `mod_push: {notify_on: messages}` avoids most of them.

Changing `RELAY_KEY` invalidates every node. Apps register on every launch, so they recover on their own.

## The command

```xml
<iq type='set' to='push.yapnest.fr' id='r1'>
  <command xmlns='http://jabber.org/protocol/commands' node='register-push-apns' action='execute'>
    <x xmlns='jabber:x:data' type='submit'>
      <field var='token'><value>hex device token</value></field>
      <field var='environment'><value>sandbox</value></field>  <!-- or production, the default -->
    </x>
  </command>
</iq>
```

The `completed` answer has a result form with one field, `node`. Executing the command without a form returns
the form to fill in.

## Env

| | |
|---|---|
| `RELAY_DOMAIN` | the component's domain, e.g. `push.yapnest.fr` |
| `RELAY_SERVER` | `host:port` of the XMPP server's component listener |
| `RELAY_COMPONENT_SECRET` | the component's shared secret |
| `RELAY_KEY` | base64 of 32 random bytes or more (`head -c32 /dev/urandom \| base64`) that seals nodes |
| `APNS_KEY` or `APNS_KEY_FILE` | the `.p8` key's contents, or its path |
| `APNS_KEY_ID`, `APNS_TEAM_ID` | from the Apple developer account |
| `APNS_TOPIC` | the app's bundle id, default `fr.yapnest.app` |
| `RELAY_METRICS_ADDR` | optional, e.g. `:9100`: where to serve [metrics](#metrics). Unset, nothing listens |

The key must allow both Sandbox and Production. Builds from Xcode get sandbox tokens; TestFlight and the App
Store get production ones.

## Metrics

With `RELAY_METRICS_ADDR` set, the relay serves Prometheus metrics on that address, apart from anything XMPP.
Unset, it opens no listener. Each replica has its own numbers: scrape both and sum them.

- `/metrics`: the metrics below.
- `/healthz`: 200 while the component is connected to the XMPP server, 503 otherwise.

| Metric | Labels | |
|---|---|---|
| `yapnest_relay_registrations_total` | `environment` (`sandbox`, `production`, `unknown` when the form named none of them), `result` (`ok`, `bad_token`, `bad_form`) | registrations |
| `yapnest_relay_publishes_total` | `result` (see below) | publishes from users' servers |
| `yapnest_relay_apns_requests_total` | `environment`, `outcome` (`ok`, `bad_request`, `forbidden`, `gone`, `too_many`, `server_error`, `network_error`) | requests to APNs. A dead token is `gone`, whichever status Apple used |
| `yapnest_relay_apns_request_duration_seconds` | `environment` | histogram of those requests, failed ones included |
| `yapnest_relay_component_connected` | | 1 while connected, else 0 |
| `yapnest_relay_component_connects_total` | `result` (`ok`, `error`) | attempts to connect |
| `yapnest_relay_throttled_devices` | | devices inside their 10 s window or with a trailing push pending |
| `yapnest_relay_build_info` | `version`, `revision` | always 1. The image build sets both; each is `unknown` when neither the build nor the binary's VCS info provides it |

The publish results: `sent` went to APNs at once; `coalesced` was absorbed by a push already sent or pending in
its window, so it has none of its own; `trailing` is a push sent at the end of a window; `unauthorized` came from
someone other than the node's account or server; `bad_node` named no valid node; `gone` is a token APNs says is dead,
answered `item-not-found` (for a trailing push, the server's next publish is pushed at once and gets that answer);
`error` is everything else that went wrong with APNs, trailing pushes included.
The Go runtime's and the process's own metrics are served too.

**Privacy:** no label or value may identify anyone: no address, domain of a user's server, device token or node,
and nothing derived from one, hashes included. Counts, like the devices in the throttle, are fine. The privacy
policy says the relay keeps nothing about who uses it, and the logs follow the same rule. Labels are fixed words,
and a test scrapes `/metrics` after the end-to-end flow to check none of those appear.

## Hosting

The domain must be reachable over s2s, like any XMPP domain:

- **DNS:** an SRV record `_xmpp-server._tcp.push.yapnest.fr` pointing at the server's s2s port, or A/AAAA records
  for `push.yapnest.fr` on that host.
- **Certificate:** the XMPP server must present one valid for `push.yapnest.fr`.
- **Listener:** the server needs a component listener with the secret. In ejabberd:

  ```yaml
  listen:
    - port: 5347
      module: ejabberd_service
      hosts:
        push.yapnest.fr:
          password: "the secret"
  ```

  In Prosody: `component_ports = { 5347 }` and `Component "push.yapnest.fr"` with `component_secret`.

Expose the listener only to the relay.

## Develop

```sh
go test ./...
```

The tests run the whole path against a fake XMPP server and a fake APNs. The integration test runs it against real
Prosody and ejabberd containers instead (it needs Docker, and is skipped without it), through registration,
enabling push and a push for an offline message:

```sh
go test -tags integration -run Integration -v ./...
```

CI runs both on every pull request.

To run the relay by hand, Yapnest's dev Prosody (`dev/prosody` in the app's repo) serves `push.localhost` with the
secret `relay`:

```sh
RELAY_DOMAIN=push.localhost RELAY_SERVER=127.0.0.1:5347 RELAY_COMPONENT_SECRET=relay \
RELAY_KEY=$(head -c32 /dev/urandom | base64) APNS_KEY_ID=… APNS_TEAM_ID=… APNS_KEY_FILE=AuthKey_….p8 go run .
```

## Release

`git tag vX.Y.Z && git push --tags`. CI runs the tests, builds the Dockerfile for amd64 and pushes
`ghcr.io/shimmerglass/yapnest-relay:vX.Y.Z` and `:latest` to GitHub's container registry.

## License

yapnest-relay is free software under the GNU Affero General Public License, version 3 or later (`NOTICE`, with
the licence's text in `LICENSE`), like the Yapnest app it serves. The Go modules it's built on keep their own
licences, listed in `go.mod`. As the licence asks of a network service, the relay names where its source is in its
disco#info reply (XEP-0232 software information, field `source`); a modified relay must point it at its own source.
