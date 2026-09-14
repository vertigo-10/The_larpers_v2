# Getting SENTRY watching your real network

Written for the Render deployment at `https://sentry-q3lz.onrender.com`, running
on a macOS machine. Assumes the repo is at `/Users/jude/The_larpers`.

---

## Read this first — what will and will not work on Render

There are two ways to feed SENTRY real traffic. **Only one of them works on your
current hosting**, and knowing which saves you an afternoon.

| Path | How it talks to SENTRY | Works on Render? |
| --- | --- | --- |
| **Collector agent** | HTTPS `POST /api/ingest` | **Yes** |
| **NetFlow / IPFIX** from a router or switch | UDP to port 2055 / 4739 | **No** |

A Render web service exposes exactly one HTTP(S) port and nothing else. NetFlow
and IPFIX are UDP protocols on their own ports, so the collector inside SENTRY
has no way to receive them there. The **Flow Sources** page and the
`SENTRY_NETFLOW_ENABLED` setting are real and they work — they just need a host
that lets you open a UDP port, which is a VPS like the Hetzner CX22 in your
hosting plan, not Render.

So: **use the collector agent.** Everything below is that path.

---

## Step 0 — Ship the current code first

The live site is running a build from before the NetFlow work. Do this before
anything else or you will be setting up against stale code.

```bash
git push origin main
```

Watch the deploy land in Render → *(your service)* → **Deploys**. If nothing
appears within a minute or two, check the **TRIGGER** column on the deploys
already listed: if every one of them says `Manual`, auto-deploy has never fired
and the push alone will not be enough.

The cause, if so, is the **Source** setting under Settings → Build. Connecting a
*public* repository by URL lets Render clone it anonymously — which works fine
for manual deploys and is why nothing looks broken — but installs no GitHub App,
so GitHub has nothing to notify on push and the Auto-Deploy toggle sits there
reading `On Commit` while being completely inert. Fix it by installing the Render
GitHub App and re-pointing **Source** at the **Git Provider** entry for the same
repo. Installing the app alone does not do it; the service stays bound to the
public-URL source until you switch it over.

Either way you can always fall back to **Manual Deploy → Deploy latest commit**.

Confirm it worked:

```bash
curl https://sentry-q3lz.onrender.com/api/health
```

You want **`{"status":"ok"}`** and nothing more. If you still see `database`,
`model` and `version` in there, the old build is still live and the deploy did
not go through.

> **Note if you are on Render's free tier:** the service sleeps after inactivity
> and takes ~30–60s to wake. The collector handles this — it retries with backoff
> and buffers up to 20,000 flows — but your first batch may take a minute to land.

---

## Step 1 — Create a collector key

1. Sign in at `https://sentry-q3lz.onrender.com`.
2. **Settings** → **Collector keys** → **New key**.
3. Copy it. It starts with `sentry_ak_`.

**The key is shown exactly once and is never recoverable.** If you lose it, revoke
it and issue a new one — that is cheaper than it sounds, since revoking a key does
not disturb anybody's login session.

Save it to a file rather than pasting it into a shell command. Arguments are
visible in `ps` to every account on the machine, which is why the collector
refuses to accept a key on the command line at all:

```bash
printf '%s' 'sentry_ak_PASTE_YOURS_HERE' > ~/.sentry-key
chmod 600 ~/.sentry-key
```

The collector checks that file's permissions on startup and refuses to read one
that is group- or world-readable.

---

## Step 2 — Install the collector's dependencies

The collector needs only `scapy` and `requests` — deliberately not the backend's
dependencies, because it is meant to run on routers and laptops that should not
have to install PyTorch to send counters over HTTP.

Your existing `.venv` already has both, so there is nothing to install. If you
ever set it up elsewhere:

```bash
pip install -r agent/requirements.txt
```

---

## Step 3 — Run it

From the **repo root** (`agent` resolves as a package relative to the working
directory, so this will fail from anywhere else):

```bash
cd /Users/jude/The_larpers

.venv/bin/python -m agent.sentry_collector \
  --server https://sentry-q3lz.onrender.com \
  --key-file ~/.sentry-key \
  --node JUDE-MAC
```

**No `sudo`** — see the next section for why, and what to do if you get a
permission error instead.

`--key-file` is doing real work here beyond convenience: the README's other form
exports `SENTRY_API_KEY` and runs under `sudo -E`, where the `-E` is not optional
because plain `sudo` wipes the environment and takes the key with it. Reading the
key from a mode-600 file has no such failure mode, under sudo or not.

You should see roughly:

```
[collector] interface=en0 node=JUDE-MAC server=https://sentry-q3lz.onrender.com
[collector] local addresses: 127.0.0.1, 192.168.68.x, 2401:…, ::1, fe80::1
[collector] capturing headers only — payloads are never read or transmitted
```

### Packet capture without root

macOS keeps the BPF capture devices at `crw------- root:wheel`, so capture
normally needs root. Two ways to get there, and the second is better:

**`sudo`** works if your account is an administrator. It is not a given: `sudo`
authorises the *invoking* user, so on a machine where your account is a standard
user, knowing an administrator's password does not help — you get `jude is not in
the sudoers file` no matter what you type.

**ChmodBPF** is the better answer and the one this machine uses. It ships with
Wireshark (tick *Install ChmodBPF* during the install; macOS accepts admin
credentials in the installer dialog without the logged-in user being an admin).
It installs a LaunchDaemon that, at every boot, moves `/dev/bpf*` into a group
called `access_bpf` and adds you to it — capture rights and nothing else, rather
than the blanket authority `sudo` would confer.

The daemon has to run at every boot because the kernel recreates those device
nodes as `root:wheel` each time; a one-off `chmod` works until the next restart
and then silently stops.

Verify it took:

```bash
ls -l /dev/bpf0                       # want: root  access_bpf  crw-rw----
groups | tr ' ' '\n' | grep access_bpf
```

If the group is missing from `groups` but the install succeeded, log out and back
in — membership only refreshes on a new login session.

### Be patient for the first ~20 seconds

Nothing appears instantly, and that is correct behaviour rather than a fault. The
collector aggregates packets into *flows* and only sends a flow once it has
expired:

- **Idle timeout: 15s** — a conversation that has gone quiet is closed and sent.
- **Active timeout: 60s** — a long-running conversation is cut and reported so an
  hour-long download still shows progress instead of appearing as one flow when
  it finally finishes.
- **Flush interval: 5s** — how often expired flows are posted.

So expect the first rows on the dashboard about 15–20 seconds in. Open a few
websites in a browser to give it something to chew on.

Stop it with `Ctrl-C`. It flushes what it is holding before exiting.

---

## Step 4 — Check the dashboard

Open **Live Overview**. You are looking for:

- Flow rows with **`source: live`**, not `simulated`.

  **Check the page subtitle first.** If it reads `all nodes · simulated traffic`,
  the simulator is running and your real flows are buried under hundreds of
  synthetic ones per minute. `SENTRY_ENV=production` turns the simulator off only
  as a *default* — an explicit `SENTRY_SIMULATOR_ENABLED` in the environment
  overrides it, and a deployment carrying that variable over from a demo looks
  correctly configured in every other way. Delete the variable in Render →
  Environment rather than setting it to `false`, so it tracks `SENTRY_ENV`
  automatically instead of becoming a second thing to keep in sync.
- A node named `JUDE-MAC` (or whatever you passed to `--node`) in the node chips
  under the chart and on the **Network Nodes** page. It is created automatically
  the first time a flow arrives naming it.
- The **Flows / min** KPI climbing above zero.

If flows arrive but every verdict is `normal`, that is the correct answer. Your
home traffic is not under attack, and a detector that found attacks in it would be
broken. To see the detection path actually fire, see *Generating something to
detect* below.

---

## What this will and will not see — read before you conclude it is broken

Running the collector on your Mac captures **traffic on that Mac's interface
(`en0`) only**. It is a sensor on one host, not a view of the whole house.

Specifically, **you will not see other devices' traffic**, and this is a property
of Wi-Fi rather than a limitation of SENTRY. On WPA2/WPA3, every client's traffic
is encrypted with its own pairwise key, so your Mac physically cannot read your
phone's or your TV's packets even in promiscuous mode. Any tool claiming otherwise
on a modern network is wrong.

To watch a whole network you need the traffic to physically reach the sensor, which
means one of:

| Approach | What it needs | Works with Render? |
| --- | --- | --- |
| Collector on one host | Nothing extra | **Yes** — this guide |
| Collector on a mirror/SPAN port | A **managed** switch (most home routers cannot do this) | Yes |
| Collector on the router itself | OpenWrt/pfSense/OPNsense that can run Python + scapy | Yes |
| **NetFlow export from the router** | A router that speaks NetFlow/IPFIX | **No** — needs UDP, so needs a VPS |

That last row is the one worth planning toward. If your router can export NetFlow
— Ubiquiti, MikroTik, pfSense, OPNsense and most OpenWrt builds can — then moving
SENTRY onto the Hetzner CX22 gets you whole-network visibility with no agent on
any machine, which is the setup the Flow Sources page was built for. That is a
reason to do the hosting move, not just a nice-to-have.

---

## Generating something to detect

Only against **your own machines**, on **your own network**. Port-scanning
anything else is illegal in most jurisdictions and will get your connection
terminated by your ISP.

With the collector running, from another machine on your LAN (or the same one),
scan your Mac:

```bash
# macOS: brew install nmap
nmap -sS -p 1-2000 192.168.1.XX      # your Mac's LAN address
```

A SYN scan across a wide port range produces exactly the flow shape the `scan`
class was trained on — many short flows, few packets each, fanning across
destination ports. Within a minute you should see `scan` verdicts on the flow
table and an incident grouped by source IP on **Alerts & Incidents**.

The slow-DoS detector needs 30+ connections held open against one `host:port` for
30s+ each while sending under 2 KB — harder to produce by hand, and you already
have coverage for it in the test suite.

---

## Running it continuously

**With ChmodBPF installed, prefer a LaunchAgent.** It runs as you rather than as
root, needs no administrator to install, and reads the key file as its owner
instead of reaching into your home directory from a root context. Same plist as
below, saved to `~/Library/LaunchAgents/com.sentry.collector.plist`, loaded with
`launchctl load ~/Library/LaunchAgents/com.sentry.collector.plist` — no `sudo`
and no `chown root:wheel`. It starts at login rather than at boot, which for a
laptop sensor is what you want anyway.

The LaunchDaemon below is the alternative when capture rights come from `sudo`
rather than from `access_bpf` membership, since in that case the collector does
need to start as root.

Create `/Library/LaunchDaemons/com.sentry.collector.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.sentry.collector</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/jude/The_larpers/.venv/bin/python</string>
    <string>-m</string><string>agent.sentry_collector</string>
    <string>--server</string><string>https://sentry-q3lz.onrender.com</string>
    <string>--key-file</string><string>/Users/jude/.sentry-key</string>
    <string>--node</string><string>JUDE-MAC</string>
  </array>
  <key>WorkingDirectory</key><string>/Users/jude/The_larpers</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/sentry-collector.log</string>
  <key>StandardErrorPath</key><string>/tmp/sentry-collector.err</string>
</dict>
</plist>
```

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.sentry.collector.plist
sudo launchctl load /Library/LaunchDaemons/com.sentry.collector.plist

# to stop it
sudo launchctl unload /Library/LaunchDaemons/com.sentry.collector.plist
```

`WorkingDirectory` is not optional — without it the `agent` package will not
resolve and the daemon will fail silently into the error log.

---

## Useful flags

| Flag | Default | When you would change it |
| --- | --- | --- |
| `--interface` / `-i` | scapy's default route (`en0` here) | Capture on a different NIC or a mirror port |
| `--node` | short hostname | The sensor's display name in the dashboard |
| `--filter` | `ip or ip6` | Any BPF expression — `not port 22` to drop your own SSH, `not host 1.2.3.4` to drop a noisy peer |
| `--flush-interval` | `5.0` | Seconds between posts |
| `--key-file` | — | Mode-600 file instead of `SENTRY_API_KEY` |
| `--insecure` | off | Skip TLS verification. **Self-signed lab servers only** — never against Render |

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `No API key` | The env var was dropped by `sudo`. Use `--key-file`, or `sudo -E`. |
| `... is readable by other users` | `chmod 600 ~/.sentry-key` |
| `That does not look like a SENTRY collector key` | You pasted an invite code (`sentry_inv_`) instead of a collector key (`sentry_ak_`). They are deliberately different prefixes. |
| `permission denied — packet capture needs root` | No capture rights. Install ChmodBPF (see *Packet capture without root*), or run under `sudo` if your account is an administrator. |
| `jude is not in the sudoers file` | Your account is not an administrator, and `sudo` authorises the invoking user — an admin's password will not help. Install ChmodBPF instead; it needs an admin once, then never again. |
| Dashboard subtitle says `simulated traffic` | `SENTRY_SIMULATOR_ENABLED` is set explicitly and is overriding `SENTRY_ENV=production`. Delete it in Render → Environment. |
| `No module named agent` | You are not in the repo root. `cd /Users/jude/The_larpers` first. |
| `401` from the server | Key was revoked, or it belongs to a different org. Issue a new one. |
| Runs clean, no flows on the dashboard | Wait 20s (see the timeout note). Then generate traffic. Then confirm you are looking at the right org. |
| Flows appear then stop | Render free-tier sleep. The collector buffers and retries; it will catch up. |
| Everything says `normal` | Correct. Your traffic is fine. See *Generating something to detect*. |

---

## What the collector does and does not send

Worth knowing, and worth being able to tell anyone else on your network:

- **It reads packet headers only.** Addresses, ports, sizes, timings. It never
  reads payloads, and only counters derived from headers are transmitted. A tool
  that watches a network should not become a way to read everyone's traffic.
- **It never takes the key on the command line**, because `ps` is readable by every
  account on the machine.
- **It buffers up to 20,000 flows** if the server is unreachable, then drops the
  oldest and logs the loss — during an attack the newest flows are the ones you
  need.
- **It warns if you post over plain HTTP** to a remote host, because the API key
  travels in a header.

---

## Summary

```bash
# once
git push origin main                                    # then verify the deploy
printf '%s' 'sentry_ak_...' > ~/.sentry-key && chmod 600 ~/.sentry-key

# every time
cd /Users/jude/The_larpers
.venv/bin/python -m agent.sentry_collector \
  --server https://sentry-q3lz.onrender.com \
  --key-file ~/.sentry-key \
  --node JUDE-MAC
```
