# Bryan's Curated Pi-hole Blocklist

First version of a maintained, category-split domain blocklist for Pi-hole.
Lists are plain text, one domain per line, ready to use as an adlist.

## Lists

| File | Category |
| --- | --- |
| `blocklist.txt` | Combined unique domains (use this as the Pi-hole adlist) |
| `ads.txt` | Advertising |
| `trackers.txt` | Trackers / telemetry |
| `malware.txt` | Malware / phishing |
| `smart-tv-iot.txt` | Smart TV / IoT telemetry |

`sources.txt` lists every upstream URL by category. `whitelist.txt` is a short
allowlist applied at build time (exact domain plus its subdomains).

## Rebuild

```bash
./build.sh
```

The script downloads each source, normalizes hosts and plain `||domain^`
adblock rules, drops comments, IPs, localhost, and invalid names, applies the
whitelist, and rewrites the list files. A failed source is reported and skipped;
the rest of the build still completes.

## Use with Pi-hole

Once this directory is hosted at a public URL (for example a GitHub repo), add
the raw `blocklist.txt` URL as an adlist in Pi-hole (Group Management → Adlists)
and run `pihole -g`. Until then, you can copy `blocklist.txt` onto the Pi and
point an adlist at a local or LAN URL.

Upstream lists keep their original licenses; this repo only redistributes
normalized domain names produced from them.
