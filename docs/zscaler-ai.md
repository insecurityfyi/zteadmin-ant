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

## Not yet checked on a live tenant

These came from Zscaler's SDKs and haven't been tried against a live tenant:

- the exact Shadow IT category name for AI apps (the category override setting covers this);
- whether the `appClass=AI_ML` filter applies to the cloud application list. If the filter is ignored, the full list comes back; Linkwatch then skips the catalogue and notes this on the page.
