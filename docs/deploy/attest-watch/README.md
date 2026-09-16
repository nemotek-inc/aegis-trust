# attest-watch — the verifier, deployed

The attestation verifier has existed since S051 with 17 checks, including a
silence check that turns *"no report arrived"* into a finding.

**Nothing ran it.** The documentation said how to invoke it; the distribution
carried no timer, no Action, no container entrypoint, and no way to tell anyone
the answer except an exit code and a line on stderr.

For a verifier that is worse than for an ordinary feature: **a check nobody runs
is indistinguishable from a check that always passes** — and this one exists to
notice that your boundary stopped reporting.

## One artifact, three shapes

`aegis attest-watch` is a long-running loop. It is the only deployment unit
shipped, deliberately:

| your operation | how to run it |
|---|---|
| systemd | the `Service` in this directory (`Restart=always`) |
| container | the image's **main process** — no cron inside, no supervisor |
| Kubernetes | a `Deployment` with **one** replica |

A cron-per-platform would be three artifacts and three ways to be
misconfigured, for the one program whose own liveness has to be legible.

## Install (systemd)

```bash
sudo useradd --system --home /var/lib/aegis-watch --shell /usr/sbin/nologin aegis-watch
sudo cp aegis-attest-watch.service /etc/systemd/system/
sudoedit /etc/systemd/system/aegis-attest-watch.service   # set the four values
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-attest-watch
```

The four values:

| | |
|---|---|
| `EXPECT_KEY` | the Ed25519 public key this deployment is pinned to (64 hex) |
| `EXPECT_HOST` | the host fingerprint this deployment is pinned to |
| `STATE` | where the silence check keeps its state — **must survive restarts**, or "no report arrived" can never be detected |
| `NOTIFY` | argv of a command that receives the verdict as JSON on stdin |

## Container

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir aegis-trust
USER 65532:65532
ENTRYPOINT ["aegis", "attest-watch"]
```

```bash
docker run --rm \
  -v /var/lib/aegis-watch:/state \
  aegis-watch \
  --expect-key "$EXPECT_KEY" --expect-host "$EXPECT_HOST" \
  --state /state/attest-state.json \
  --report-within 7200 \
  --heartbeat /state/heartbeat.json \
  --notify-command "/usr/local/bin/page-oncall" \
  --renotify 21600 --every 3600
```

## Proving it runs, instead of believing it

Every cycle writes the heartbeat file:

```json
{
  "cycle": 42,
  "verdict": "clean",
  "exit_code": 0,
  "finished_at": 1789000000.0,
  "notified": false,
  "notify_error": null,
  "notify_reason": "clean"
}
```

Point your own monitoring at its **age**. If it stops being written, the watcher
is not running — and that is a fact about the watcher, which no amount of "the
service says active" can substitute for.

To test the deployment without waiting a period:

```bash
aegis attest-watch --max-cycles 1 ...   # one check, then exit
```

`--max-cycles 1` behaves exactly like a single `attest-verify`, including its
exit code.

## When it tells you

| verdict | exit | notifies |
|---|---:|---|
| `clean` | 0 | never — a watcher that pages on success is a watcher people mute |
| `abnormal` | 1 | yes |
| `no_report` | 2 | yes — **a different emergency** from `abnormal`, so moving between them notifies immediately |

While a bad verdict persists it is repeated every `--renotify` seconds. Without
that flag a persistent problem is announced **once**, and to anyone who joined
after that day it reads like no problem at all.

## What this does not do

* It does not open your capsule directory. It verifies an attestation and
  nothing else — two implementations answering one question about one disk is
  how you get told two different things.
* It does not deliver the notification itself. `--notify-command` is your
  script, run as argv and **never through a shell** (a webhook URL or token is
  exactly the value that turns `shell=True` into command execution).
* **It cannot notify you if you did not configure `--notify-command`.** The
  heartbeat records that, and the process says so on startup. It will not
  pretend a bad verdict was delivered.
