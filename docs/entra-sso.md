# Microsoft Entra ID single sign-on (SAML)

People sign in to VisCon1 with their Microsoft work account. Entra checks the
password, MFA and Conditional Access. VisCon1 then gives them admin or
read-only access based on their Entra **app role** or **group**. The local
`admin` account (from `LW_ADMIN_PASSWORD`) keeps working as a break-glass
login, and `deploy/reset-password.sh` still resets it.

The examples use `https://utilz.perrego.net`. Everything is in
**Administration > Single sign-on**, which also shows the exact values with copy buttons.

| VisCon1 value | Use it for |
|---|---|
| `https://utilz.perrego.net/saml/metadata` | Identifier (Entity ID) |
| `https://utilz.perrego.net/saml/acs` | Reply URL (Assertion Consumer Service URL) |
| `https://utilz.perrego.net/saml/login` | Sign on URL |

These come from `LW_PUBLIC_URL` in `~/.config/linkwatch/linkwatch.env`. It must be
the https address people use, or Entra's reply won't match.

## 1. Create the enterprise application

1. Go to [entra.microsoft.com](https://entra.microsoft.com) and sign in as a Cloud Application Administrator or Application Administrator.
2. Open **Identity > Applications > Enterprise applications > New application > Create your own application**.
3. Name it `VisCon1`, choose **Integrate any other application you don't find in the gallery (Non-gallery)**, then click **Create**.
4. In the new app, open **Properties** and check that **Assignment required?** is **Yes**. Only the people and groups you assign can sign in. Save.

## 2. Set up SAML

1. In the app, open **Single sign-on > SAML**.
2. Under **Basic SAML Configuration**, click **Edit** and enter:
   - **Identifier (Entity ID):** `https://utilz.perrego.net/saml/metadata`. Tick it as the default.
   - **Reply URL:** `https://utilz.perrego.net/saml/acs`
   - **Sign on URL:** `https://utilz.perrego.net/saml/login`
   - Leave **Relay State** and **Logout Url** empty.

   You can use **Upload metadata file** with `linkwatch-sp-metadata.xml` from the VisCon1 page instead. Save.
3. Under **Attributes & Claims**, keep the defaults. VisCon1 uses:
   - `name` (user principal name) as the username;
   - `emailaddress`, `displayname` and `objectidentifier`.

   Guests are named by their email address.
4. Under **SAML Certificates**:
   - Leave the signing option as **Sign SAML assertion** with **SHA-256**. VisCon1 also accepts "Sign SAML response and assertion".
   - Copy **App Federation Metadata Url**. You'll need it in step 5.
5. Don't turn on **Token encryption**. VisCon1 refuses encrypted assertions.

## 3. Decide who gets which role

Use **one** of these two options. App roles are the better choice: they always fit in the token, and their names are readable.

### Option A: app roles (recommended)

1. Go to **Identity > Applications > App registrations > All applications > VisCon1 > App roles > Create app role**. Create two roles:

   | Display name | Allowed member types | Value | Description |
   |---|---|---|---|
   | VisCon1 admin | Users/Groups | `VisCon1.Admin` | Full access |
   | VisCon1 read-only | Users/Groups | `VisCon1.ReadOnly` | View only |

2. Go back to **Enterprise applications > VisCon1 > Users and groups > Add user/group**.
3. Pick the people or groups, then the role, then click **Assign**.

   Assigning a group to an app role needs Entra ID P1 or P2. On the free tier, assign users one at a time.

Entra sends the role in the `.../claims/role` claim automatically.

### Option B: security groups

1. In **Single sign-on > Attributes & Claims**, click **Add a group claim**.
2. Choose **Groups assigned to the application**, and set **Source attribute** to **Group ID**. Save.
3. Assign the groups under **Users and groups**.
4. Note each group's **Object ID** (from **Groups > the group > Overview**). You'll paste these into VisCon1.

Choosing "All groups" instead can break sign-in for people in more than 150
groups. In that case Entra sends a link instead of the groups, and VisCon1 says so.

## 4. Give it a test user

Assign yourself under **Users and groups**, with the admin role or in the admin group.

## 5. Configure VisCon1

Sign in as an admin and open **Administration > Single sign-on**.

1. **App Federation Metadata URL:** paste the URL from step 2.4. The server downloads it now and again once a day, so Entra certificate renewals are picked up automatically.
   - The VPS needs outbound HTTPS to `login.microsoftonline.com` for this.
   - If it can't reach it, download **Federation Metadata XML** from the same section in Entra and paste it under "Or paste the Federation Metadata XML".
2. **Who gets admin:**
   - with app roles: `VisCon1.Admin`;
   - with groups: the admin group's Object ID.
3. **Who gets read-only:**
   - with app roles: `VisCon1.ReadOnly`;
   - with groups: the Object IDs.

   You can enter several values, separated by commas.
4. **Anyone else assigned to the app:** leave this as *Can't sign in*. Choose *Gets read-only* only if assignment in Entra is all the control you want.
5. **Create accounts on first sign-in:** leave it on. If you turn it off, an admin must first create each user with their Entra user name (UPN).
6. **Update the role from Entra at every sign-in:** leave it on. Removing someone's role or group takes effect at their next sign-in. To cut someone off at once, disable their account in **Administration > Users** as well.
7. **Password sign-in:** set it to *Only local admins (break-glass)* once SSO works, so read-only users can't sign in with an old local password. The `admin` account keeps working either way.
8. Tick **Turn on single sign-on** and click **Save**.
9. Click **Test sign-in in a new tab**. Keep your current admin tab open until it works.

The sign-in page now shows **Sign in with Microsoft**. The password form is
under "Sign in with a password". The **VisCon1** tile in My Apps (myapps.microsoft.com) also works,
because it opens the Sign on URL.

## How it is secured

- The sign-in starts in VisCon1. The response must:
  - answer that exact request, within 10 minutes;
  - be signed by the certificate from your Entra metadata;
  - name VisCon1's Entity ID as the audience and its Reply URL as the recipient;
  - fall within its validity window (3 minutes of clock skew allowed);
  - not have been used before.
- Only the signed part of the response is read, which defeats signature-wrapping attacks.
- Sign-ins started from Entra itself (the **Test** button in Entra) are refused unless you tick "Accept sign-ins started in Entra". Use the VisCon1 test button instead.
- SSO users have no VisCon1 password.
- Every SSO sign-in, failure, role change and account creation goes in the audit log.
- Signing out of VisCon1 doesn't sign you out of Microsoft.

## Troubleshooting

| What you see | Fix |
|---|---|
| `AADSTS50011` reply URL mismatch | The Reply URL in Entra must be exactly `https://utilz.perrego.net/saml/acs`. Check that `LW_PUBLIC_URL` is https. |
| `AADSTS700016` application not found | The Identifier in Entra must be exactly the Entity ID shown in VisCon1. |
| `AADSTS50105` user not assigned | Assign the user, or one of their groups, under **Users and groups**. |
| "isn't in an Entra group or app role that is allowed" | The role value or group Object ID in VisCon1 doesn't match what Entra sent. Check the spelling of `VisCon1.Admin`, or the group claim setup. |
| "signature didn't verify" | The Entra certificate changed. Click **Refresh metadata now**, or paste the new metadata XML. |
| "expired or isn't valid yet" | The VPS clock is off. Run `timedatectl` and check that NTP is on. |
| Locked out completely | On the VPS, run `deploy/reset-password.sh`, then sign in as `admin` with a password. |
