# BTS Cluster Web

Small local web UI for finding Raspberry Pi YateBTS nodes in one subnet and
running basic operations against them.

## Run

```bash
python3 -m pip install -r requirements.txt
python3 bts_cluster/server.py --host 127.0.0.1 --port 8097
```

Open:

```text
http://127.0.0.1:8097/
```

## Features

- scan a CIDR subnet for nodes with SSH `22` and/or Yate telnet `5038`;
- verify default Raspberry Pi credentials `pi` / `raspberry` when `sshpass`
  is installed;
- add nodes manually by IP;
- track per-node `Radio.Band` / `Radio.C0` and `MS.IP.Base` / `MS.IP.MaxCount`,
  preventing duplicate IP, duplicate ARFCN, or overlapping MS IP pool assignments;
- start, restart, or stop `yate.service` over SSH;
- set Yate rmanager `addr=0.0.0.0` on a node without changing the telnet port;
- send custom Yate telnet/rmanager commands;
- use built-in telnet command templates.
- continuously stream remote logs with `tail -F`, for example
  `/var/log/yate.err`.

Runtime inventory is stored outside git in `.bts_cluster_web/inventory.json`.
The server binds to localhost by default because it can hold SSH credentials.

## Notes

For password-based SSH automation install `sshpass` on the controller machine.
Without it, scanning still detects open SSH/telnet ports, but password login and
service actions require key-based SSH access or `sshpass`.

If `/var/log/yate.err` is not readable by the `pi` user, enable the UI checkbox
`Read through sudo`. Password sudo needs the node password saved in inventory;
key-only nodes need passwordless sudo for `tail`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
