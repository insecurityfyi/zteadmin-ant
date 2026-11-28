# VisCon1 as an app (install, offline, alert notifications)

VisCon1 is a Progressive Web App (PWA). There is nothing to download from an app store: the browser
installs it from the portal itself, and it updates whenever the server does.

## Install it

| Device | How |
| --- | --- |
| iPhone, iPad (iOS/iPadOS 16.4 or later) | Open the portal in **Safari**, tap **Share**, then **Add to Home Screen**. |
| Android | Chrome or Edge offers **Install app**; otherwise menu › **Add to Home screen**. |
| Windows, macOS, Linux, ChromeOS | Chrome or Edge: the install icon at the right of the address bar, or menu › **Install VisCon1**. Safari on macOS: **File › Add to Dock**. |

**Your account › App and alert notifications** shows an **Install VisCon1** button where the browser allows it,
and the steps for the others. The installed app opens in its own window with the VisCon1 icon for the site
theme. Long-pressing (or right-clicking) the icon offers shortcuts to the dashboard, open alerts, the network
map and devices. SSH and remote desktop pop-outs open as their own windows as before.

The app always loads live pages from the server; nothing about your network is stored on the device.
When the server can't be reached it shows an offline page that reconnects by itself.

## Alert notifications

Under **Your account › App and alert notifications** press **Turn on notifications** on each phone, tablet or
computer that should get them, and choose what to be told about (critical only, warning and critical, or
everything). **Send a test** checks the device right away. Every user can do this, including read-only users.

* Notifications cover the same alerts as the other transports under **Settings › Where alerts are sent**:
  alerts opening and resolving. A resolve replaces the notification of the alert it resolves, and critical
  alerts stay on screen until dismissed (where the system allows it).
* Tapping a notification opens VisCon1 at the alert list.
* On iPhone and iPad, notifications work only from the installed app (Home Screen icon), not from a Safari tab.
* The list under the buttons shows each device you turned on. Remove one there, or press **Turn off on this
  device** on the device itself. Devices the push service reports as gone are removed automatically.

### How it works and what the server needs

VisCon1 uses standard Web Push: no Firebase, Apple developer account or third-party service to sign up for.
The server makes its own key pair (VAPID) on first start and keeps it, encrypted with `LW_SECRET_KEY`, in the
database. Each notification is encrypted for the receiving device, so the push service (Google, Apple, Mozilla
or Microsoft, depending on the browser) can't read it.

* The site must be served over **HTTPS** (it is behind nginx with a certificate).
* The VisCon1 server must be able to reach the push services over HTTPS:
  `fcm.googleapis.com`, `*.push.apple.com`, `*.push.services.mozilla.com` and `*.notify.windows.com`.
  Subscriptions to any other address are refused.
* Optional: `LW_PUSH_CONTACT` sets the contact address push services see (an email address or https URL).
  It defaults to `LW_PUBLIC_URL`.
