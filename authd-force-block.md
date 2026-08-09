# authd change needed for automated re-enrollment

Your current `<auth>` block has no `<force>` section, so authd falls back to
its defaults. On Wazuh 4.x the defaults will refuse to replace an agent that
is currently *connected* under the same name — which is exactly what happens
when Intune re-runs the installer on a machine that is still online, or when
a device is reimaged and comes back with the same hostname.

Add this inside the existing `<auth>` block in `wazuh_manager.conf`:

```xml
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>

    <!-- NEW: lets a rebuilt / re-enrolled host reclaim its own name -->
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="no">1h</disconnected_time>
      <after_registration_time>0</after_registration_time>
    </force>

    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_agent_ca>/var/ossec/etc/agents-rootCA.pem</ssl_agent_ca>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
```

What changed and why:

- `disconnected_time enabled="no"` — replace an agent with a duplicate name
  even if it is still showing as active. Without this, re-running the Intune
  installer on a live machine fails with a duplicate-name error.
- `after_registration_time 0` — no minimum age before a registration can be
  replaced. With the default `1h`, a machine that enrolls and then fails and
  retries 5 minutes later gets rejected.
- `key_mismatch yes` — replace when the agent presents a key the manager
  doesn't recognise, which is the reimaged-host case.

The trade-off is real and worth stating: with `disconnected_time` disabled,
anyone who can pass authd's checks can take over an existing agent's name and
push the legitimate host out. That is acceptable *because* the client cert
requirement (`ssl_agent_ca`) plus the enrollment password gate who can reach
this point at all. If you ever drop the client cert requirement, tighten this
back up.
