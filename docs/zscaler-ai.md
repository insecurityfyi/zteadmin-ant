# Zscaler: the AI tab

The Zscaler integration page has an **AI** tab. It shows which generative AI apps
people use, how ZIA's policy treats them, and which DLP rules cover them. It uses the
same OneAPI client as the rest of the integration. You can switch it off with
**Generative AI usage and policy** in the integration settings.

Zscaler doesn't offer a dedicated "AI telemetry" API. The tab combines what OneAPI
does expose:

| Panel | Source | Notes |
|---|---|---|
| AI apps in use: users, data uploaded and downloaded, risk, sanctioned state, last used | Z-Insights `SHADOW_IT.apps` (POST `/zins/graphql`) | Covers the 7 days ending at midnight UTC yesterday, because Z-Insights runs 24 to 48 hours behind. |
| AI users and data totals, share of all SaaS traffic | Z-Insights `SHADOW_IT.shadow_it_summary` | Grouped by app category. |
| AI & ML rules: allow, caution, block or isolate; apps; who they apply to; prompt capture; isolation profile; quotas | `GET /zia/api/v1/webApplicationRules/AI_ML` | |
| Policy column in the apps table | Worked out from the rules above | Shows the first enabled rule that names the app, or a rule covering all AI apps. Rules can be limited to some users, groups or locations, so other people may get a different action. |
| ZIA's AI app catalogue | `GET /zia/api/v1/cloudApplications/policy?appClass=AI_ML` | Used to recognise AI apps in Shadow IT and to show app names. |
| DLP rules covering AI | `GET /zia/api/v1/webDlpRules` | Rules that name an AI app or the `AI_ML_APPS` or `GENERAL_AI_ML` URL categories. |
| AI Guard | `GET /aiguard/v1/detections/policies`, `/aiguard/v1/llm-applications`, `/aiguard/v1/llm-providers` | Configuration only. Needs an AI Guard licence. |

Each source is optional. If the API client lacks a role or the tenant lacks a licence,
that one panel is empty and the reason is listed under "optional panels not available".

## Which apps count as AI

An app counts as AI if either of these is true:

- its Shadow IT category has "AI", "ML", "generative", "artificial", "machine learning" or "LLM" in its name;
- it is in ZIA's AI & ML app catalogue.

If your tenant names the category differently, set **Shadow IT category for AI apps**
in the integration settings. With that set, only that category counts. When no AI apps
match, the tab lists the categories it did see, so you can pick the right one.

## Refresh and rate limits

The AI data is fetched at most once an hour, however often the integration syncs.
That keeps it well inside ZIA's limits (400 an hour for the rules endpoint) and suits
data that only changes daily. A failed fetch isn't cached, so it is retried on the
next sync.

## Not available through the API

The tab says so on the page, too:

- **Prompts and responses.** Prompt capture is a rule setting. The captured prompts can only be viewed in the admin portal.
- **Allowed versus blocked request counts per AI app.** Z-Insights web traffic can't be grouped by app.
- **Top users and departments per AI app.** Only the portal's Shadow IT CSV export has this, and it is limited to a few reports an hour.
- **DLP incidents on AI prompts.** The API returns DLP rules, not incidents. Stream incidents to a SIEM with Nanolog Streaming Service.
- **Isolation sessions.** Only isolation profiles are exposed.
- **AI Guard detections.** AI Guard's API returns configuration and scans content on request, but keeps no detection history.

## API client roles

In ZIdentity, the API client needs:

- ZIA read access to Cloud App Control, DLP and cloud applications;
- Z-Insights (Analytics) access for the usage panels;
- AI Guard, if you use it.

For control actions it needs more; see the next section.

## Control actions

Admins can change Zscaler's generative AI policy from the AI tab. It is off until you tick
**Allow control actions** in the integration settings, and it works like the Proxmox and
Synology pages:

- only admins see the buttons, and the server refuses the request from anyone else;
- the integration must have **Allow control actions** ticked, checked on every request;
- every action asks for confirmation, and deleting a rule or AI Guard object, or regenerating
  a credential, needs its name typed;
- every action, whether it worked or failed, is written to the audit log (Administration)
  and the event log, with who did it and what changed. Rule contents, the JSON you save and
  text you scan are never logged.

### What you can do

| Where | Action | API call |
|---|---|---|
| AI & ML rules table | Change the action (allow, caution, block, isolate), enable or disable, turn prompt capture on or off, delete | `GET`, then `PUT` or `DELETE` `/zia/api/v1/webApplicationRules/AI_ML/{id}` |
| AI & ML rules: **New rule**, or a rule's name | Create or edit a rule: name, order, enabled, actions (including the finer ones ZIA offers, such as blocking uploads), AI apps, prompt capture | `POST /zia/api/v1/webApplicationRules/AI_ML`, `PUT .../{id}`, `POST .../availableActions` |
| AI apps table | Sanction or unsanction an app | `GET /zia/api/v1/cloudApplications/lite` to find its ID, then `PUT /zia/api/v1/cloudApplications/bulkUpdate` |
| Banner, rule page | Activate pending ZIA changes | `POST /zia/api/v1/status/activate` |
| AI Guard panel | Create, edit (as JSON) or delete detection policies, policy match rules, LLM applications and LLM providers; enable or disable match rules | `/aiguard/v1/detections/policies`, `/aiguard/v1/detections/policy-match-rules`, `/aiguard/v1/llm-applications`, `/aiguard/v1/llm-providers` |
| AI Guard panel | Regenerate or delete an application credential | `POST /aiguard/v1/llm-application-credentials/{id}/regenerate`, `DELETE .../{id}` |
| AI Guard panel: **Scan text** | Check a prompt or a model's answer against your AI Guard policy | `POST https://api.<cloud>.zseclipse.net/v1/detection/execute-policy` (or `resolve-and-execute-policy`) |

Things to know:

- **ZIA changes are pending until activated**, as in the admin portal. The AI tab shows a
  banner with an **Activate now** button while ZIA has pending changes. Activating pushes
  every pending change, including changes other admins made in the portal.
- Editing a rule keeps everything the page doesn't show: who it applies to (users, groups,
  departments, locations), time windows, quotas and the isolation profile. Set those in the
  ZIA admin portal.
- Isolating needs an isolation profile on the rule. If the rule has none, the page says so
  instead of sending a change ZIA would refuse.
- The prompt capture switch only appears when ZIA returns a prompt capture setting for the rule.
- AI Guard changes take effect straight away; AI Guard has no activation step.
- AI Guard objects are edited as JSON, exactly as AI Guard's API takes them. Saving replaces
  the whole object. Secrets, such as a provider's API key, are shown as `••••••`; leave
  them as they are to keep them.
- A regenerated credential's new secret is shown once, on its own page. It isn't stored
  in Linkwatch or written to any log.
- When Zscaler refuses a change, the page and the audit log show Zscaler's own message,
  such as a duplicate rule name or a missing role.
- After each action the AI tab re-reads the rules, AI Guard and activation state, so it
  reflects the change straight away. Shadow IT usage figures still refresh hourly.

### Roles for control

In ZIdentity, edit the API client and give it:

| For | Role |
|---|---|
| Rule changes and app sanctioning | A ZIA admin role with **full** (not view-only) policy access to Cloud App Control and to cloud applications / Shadow IT |
| Activate now | The same ZIA role must be allowed to activate changes |
| AI Guard changes | An AI Guard role with write access to policies, match rules, LLM applications, providers and application credentials |
| Scan text | Not a ZIdentity role: an **AI Guard API key** from the AI Guard portal, pasted into the integration settings, plus the AI Guard cloud (`us1` by default; the `us1` in `api.us1.zseclipse.net`). Zscaler only offers the detection API with its own key, not through OneAPI. |

Keep a read-only API client if you don't want control: the AI tab works without these roles.

### Not yet checked on a live tenant

The control actions follow Zscaler's Python SDK (zscaler-sdk-python 1.11) and haven't been
tried on a live tenant. In particular:

- the name of ZIA's prompt capture field on AI & ML rules (`promptCaptureEnabled`), which is
  why the switch only appears when ZIA returns it;
- the shape of the regenerate-credential answer (the page says so if it can't find the new
  secret, and you can copy it from the AI Guard portal);
- the exact ZIdentity role names, which Zscaler words differently in different consoles.

## Not yet checked on a live tenant

These came from Zscaler's SDKs and haven't been tried against a live tenant:

- the exact Shadow IT category name for AI apps (the category override setting covers this);
- whether the `appClass=AI_ML` filter applies to the cloud application list. If the filter is ignored, the full list comes back; Linkwatch then skips the catalogue and notes this on the page.
