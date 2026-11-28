# Zscaler Cloud NSS logs in VisCon1

VisCon1 can receive Zscaler Internet Access (ZIA) logs straight from the Zscaler cloud. A **Cloud NSS feed**
pushes web, firewall and DNS logs as JSON over HTTPS. You don't need an NSS VM, a syslog server or a SIEM
in between. VisCon1 stores them under a **hard size cap (120 GB by default)**. Once the cap is reached it
deletes the **oldest** logs to make room, so retention is set by size, not by days.

What you get:

* **Logs › User activity** shows top users, top apps and categories, the most blocked users and apps, users with
  threats, and events per hour. You can view the last hour, 24 hours, 7 days, 30 days or everything stored.
* **Per-user drill-down**: click any user to see their apps, traffic, blocked activity and recent events.
* **Event search** finds individual records by host, app, category, user, IP, threat, log type or *blocked only*.
  It shows each record as Zscaler sent it.
* **Administration › Zscaler log feeds** holds the feed tokens, the endpoint URL, what has been received, storage
  use and the size cap.

This is separate from the Zscaler **API** integration (Integrations › Zscaler, OneAPI), which reads configuration,
ZDX, AI usage and so on. You can use either one or both.

> Cloud NSS is a ZIA add-on subscription. If **Cloud NSS Feeds** is missing under Nanolog Streaming Service,
> ask your Zscaler account team to enable it.

## 1. Update VisCon1 and the reverse proxy (once)

1. Update as usual (`deploy/update.sh`, or wait for the auto-update timer). The update installs a new
   `linkwatch-nss` volume, mounted in the web container at `/var/lib/linkwatch/nss`, where the logs are kept.
2. nginx is set up only once by the bootstrap script, so add the new block by hand. In
   `/etc/nginx/conf.d/<your domain>.conf`, inside the `server { … listen 443 … }` block and above `location / {`, add:

   ```nginx
   # Zscaler Cloud NSS feeds push batches of logs here
   location /api/nss/ {
       proxy_pass http://127.0.0.1:8080;
       proxy_http_version 1.1;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       client_max_body_size 64m;
       proxy_read_timeout 120s;
       access_log off;
   }
   ```

   Then run `sudo nginx -t && sudo systemctl reload nginx`. The same block is in `deploy/nginx/utilz.perrego.net.conf`.
3. The endpoint must be reachable from the internet on 443 with a publicly trusted certificate. The existing
   Let's Encrypt setup covers that.

## 2. Create a feed token in VisCon1

1. Go to **Administration › Zscaler log feeds** (also under the **Logs** menu, *Feeds and storage*).
2. Under **Feed tokens**, name the token (for example `ZIA web logs`) and press **Create token**.
3. Copy the value shown (`Bearer vcnss_…`). It is shown only once, and only its hash is stored.

Create one token per feed (web, firewall, DNS). That way you can revoke one feed without touching the others.
Deleting a token makes that feed get `401 Unauthorized` straight away.

## 3. Add the Cloud NSS feed in the ZIA admin portal

In the ZIA admin portal go to **Administration › Nanolog Streaming Service › Cloud NSS Feeds** and press
**Add Cloud NSS Feed**. Fill in the form as follows. Zscaler renames labels from time to time; the meaning stays the same.

| Field | Value |
| --- | --- |
| Feed Name | e.g. `VisCon1 web logs` |
| NSS Type | **NSS for Web** for web, DNS and tunnel logs; **NSS for Firewall** for firewall logs |
| Status | Enabled |
| SIEM Rate | Unlimited |
| SIEM Type | **Other** |
| OAuth 2.0 Authentication | Off |
| Max Batch Size | Leave the default. VisCon1 accepts batches up to 64 MB. |
| API URL | `https://<your VisCon1 host>/api/nss/ingest/web`. Use `/fw` for firewall and `/dns` for DNS. The plain `…/api/nss/ingest` works too: VisCon1 works out the type from the record. |
| HTTP Headers | Key `Authorization`, Value `Bearer vcnss_…` (the token from step 2). Optionally add a second header, Key `Content-Encoding`, Value `gzip`, to compress batches (VisCon1 handles both). |
| Log Type | **Web Log**, **Firewall Logs** or **DNS Logs** (one per feed) |
| Feed Output Type | **JSON** |
| JSON Array Notation | Either. VisCon1 reads newline-separated objects and JSON arrays. |
| Feed Escape Character | Leave the default for JSON |
| Feed Output Format | Leave the default that **JSON** fills in, or paste a format from section 4 |
| User Obfuscation | Off, or user names show as hashes on the dashboard |
| Timezone | GMT/UTC (VisCon1 shows times in UTC) |
| Filters | Optional. For example, send only some locations or departments. Every record sent counts towards the cap. |

Press **Validate**. VisCon1 answers `200 {"ok": true, …}` to a valid token (even with an empty test batch),
`401` to a missing or wrong token, and `400` if the body isn't JSON. **Save**, then **Activate** the pending changes
(the bell at the top of the portal). Logs usually start arriving within a few minutes.

Repeat for a **Firewall Logs** feed (NSS for Firewall, `…/ingest/fw`) and a **DNS Logs** feed (`…/ingest/dns`).

### Checking it works

* **Administration › Zscaler log feeds › Receiving** shows records accepted per log type, the last batch, rejected
  batches and the last problem (for example *not JSON at character 12*).
* Each token shows when it was last used, from which IP and how many records it has delivered.
* In ZIA, the feed's status on the Cloud NSS Feeds page shows delivery errors on Zscaler's side.

## 4. Feed output formats

VisCon1 reads the field names of Zscaler's default JSON (Splunk-style) templates. It also reads the raw NSS
variable names (`login`, `urlcat`, `eurl`, `csip` and so on), so the default format from **Feed Output Type: JSON**
works as it is. If you write your own, the fields VisCon1 uses are the time (`epochtime` or `datetime`), user,
department, location, app or category, host or URL, action, threat, client and server IP, and byte counts.
Anything else is kept in the stored record and shown under **Record as received**.

The compact formats below cover everything the dashboard uses. If the portal rejects a variable (variable names
differ slightly between ZIA releases), delete that `"key":"value"` pair. VisCon1 doesn't need any single field
except a timestamp, and without one it uses the time the record arrived.

**Web Log**

```
\{ "sourcetype" : "zscalernss-web", "event" : \{"datetime":"%s{time}","epochtime":"%d{epochtime}","user":"%s{elogin}","department":"%s{edepartment}","location":"%s{elocation}","appname":"%s{appname}","appclass":"%s{appclass}","urlcategory":"%s{urlcat}","urlsupercategory":"%s{urlsupercat}","hostname":"%s{ehost}","url":"%s{eurl}","action":"%s{action}","reason":"%s{reason}","threatname":"%s{threatname}","malwarecategory":"%s{malwarecat}","riskscore":"%d{riskscore}","requestmethod":"%s{reqmethod}","status":"%s{respcode}","requestsize":"%d{reqsize}","responsesize":"%d{respsize}","transactionsize":"%d{totalsize}","ClientIP":"%s{cip}","serverip":"%s{sip}","useragent":"%s{eua}","devicehostname":"%s{devicehostname}","deviceowner":"%s{deviceowner}"\}\}
```

**Firewall Logs**

```
\{ "sourcetype" : "zscalernss-fw", "event" : \{"datetime":"%s{time}","epochtime":"%d{epochtime}","user":"%s{elogin}","department":"%s{edepartment}","locationname":"%s{elocation}","csip":"%s{csip}","csport":"%d{csport}","cdip":"%s{cdip}","cdport":"%d{cdport}","proto":"%s{ipproto}","nwapp":"%s{nwapp}","nwsvc":"%s{nwsvc}","action":"%s{action}","rulelabel":"%s{erulelabel}","threatname":"%s{threatname}","inbytes":"%ld{inbytes}","outbytes":"%ld{outbytes}","devicehostname":"%s{devicehostname}"\}\}
```

**DNS Logs**

```
\{ "sourcetype" : "zscalernss-dns", "event" : \{"datetime":"%s{time}","epochtime":"%d{epochtime}","user":"%s{elogin}","department":"%s{edepartment}","location":"%s{elocation}","reqaction":"%s{reqaction}","resaction":"%s{resaction}","reqrulelabel":"%s{reqrulelabel}","resrulelabel":"%s{resrulelabel}","dns_reqtype":"%s{reqtype}","dns_req":"%s{req}","dns_resp":"%s{res}","category":"%s{domcat}","clt_sip":"%s{cip}","srv_dip":"%s{sip}","devicehostname":"%s{devicehostname}"\}\}
```

How VisCon1 classifies records:

* **Log type** comes from the URL (`/web`, `/fw`, `/dns`), otherwise from `sourcetype`, otherwise from which fields are present.
* **Blocked**: the action (or, for DNS, the request or response action) contains *block*, *drop*, *deny*, *reset*,
  *reject* or *quarantine*. *Caution* and *Isolate* count as allowed.
* **App**: web uses `appname`, falling back to the URL category; firewall uses `nwapp`, then `nwsvc`; DNS uses the
  DNS app, then the category.
* Values Zscaler uses for "nothing" (`None`, `NA`, `N/A`, empty) are treated as empty.

## 5. Storage: the 120 GB cap

* Logs are written to segment files of about 1% of the cap (1.2 GB at 120 GB) in `/var/lib/linkwatch/nss` on the
  `linkwatch-nss` volume. Each segment holds its events, their compressed original records and an hourly summary
  that the dashboard reads.
* Before each batch is written, VisCon1 adds up the size of every segment on disk. If the batch would take the
  total over the cap, it **deletes the oldest segment** (and keeps going until the batch fits). The cap is checked
  against real file sizes, so it is a hard limit, not an estimate. The dashboard's summaries go with the events
  they describe, so the dashboard never shows anything older than the stored logs.
* **Keep free (GB)** (default 10 GB) is a second guard. If the disk's free space falls below it for any reason
  (database growth, images, backups), the oldest logs are rolled off too. If the disk is nearly full anyway,
  VisCon1 refuses the batch with `507` rather than fill the disk, and the feed shows a delivery error in ZIA.
* On a 200 GB VPS the defaults leave about 70 GB for the OS, the database, container images and headroom.
* Change both values under **Administration › Zscaler log feeds › Storage**. Lowering the cap rolls off the excess
  straight away. **Delete all stored logs** (type `DELETE`) empties the store.
* As a rough guide, a web log record takes about 600 bytes on disk, so 120 GB holds about 200 million records.
  How many days that covers depends on your traffic. The Storage panel shows the oldest log still kept.

## Security notes

* The endpoint accepts only requests that carry a valid feed token. Tokens are stored as SHA-256 hashes, and after
  20 failed attempts in 15 minutes from one IP that IP is refused for a while.
* Every token created or deleted, cap change and full delete is written to the audit log.
* Read-only users can view the activity pages but can't see tokens or change storage.
* For extra safety you can limit `/api/nss/` in nginx to Zscaler's published Cloud NSS egress ranges (see Zscaler's
  *Cloud NSS IP addresses* help page), for example with `allow …; deny all;` inside the location block.
* Logs hold user names, URLs and IPs. Anyone with a VisCon1 account can see them, so give read-only accounts only to
  people who should.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Validate fails with 401 | The header must be `Authorization` with value `Bearer vcnss_…` (with the word *Bearer* and a space). Create a new token if you didn't copy the old one. |
| Validate fails with 413 | nginx is still at the 10 MB default: add the `/api/nss/` block from step 1. |
| Validate fails with a connection or TLS error | The VPS must be reachable on 443 from the internet with a valid certificate (`curl -I https://<host>/healthz` from outside). |
| *Rejected batches* goes up, last problem *not JSON …* | The Feed Output Format isn't valid JSON. Start again from the default JSON format, or check the escape character is the JSON default. |
| Users show as `(no user)` | The format has no user field, or traffic is unauthenticated (for example, location-based without surrogate IP). |
| Admin page says the store isn't writable | The container needs the `linkwatch-nss` volume. Run `deploy/update.sh` so the new quadlet unit is installed, then check `podman volume inspect linkwatch-nss`. |
