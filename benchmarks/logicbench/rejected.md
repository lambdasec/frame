# Rejected / not included candidates

One line per candidate: advisory, project, class it would have had, reason.

## Fix missing, ineffective or not application code

- GHSA-m83v-mmqj-7jrm (CVE-2024-58248) nopCommerce, race (gift card double redeem at order placement, C#): the fix faf8ec00 (#7325) only adds an opt-in `PlaceOrderWithLock` setting that defaults to false, so the "fixed" commit is still vulnerable by default.
- GHSA-c893-4f2j-x5ch (CVE-2024-50944) SimplCommerce, limits (cart quantity integer overflow, C#): fix e42ceaac checks `quantity > int.MaxValue` and `cartItem.Quantity + quantity > int.MaxValue` on `int` values; both are no-ops (int addition wraps first), so the fixed side is still vulnerable.
- GHSA-326h-w5x2-4vrm (CVE-2025-10778) Smartstore, race (gift voucher at checkout, C#): VulDB-only record, no fix commit referenced or identifiable.
- GHSA-xcww-23jc-699x (CVE-2025-10216) GrandNode2, race (/checkout/ConfirmOrder, C#): VulDB-only, no fix commit.
- GHSA-r82c-hj94-463x, GHSA-v5wh-356j-jg3c, GHSA-gg5p-jmwj-r84m macrozheng/mall, race / incorrect calculation (Java): VulDB records "up to 1.0.3", no fix commits.
- GHSA-xf6v-w5fp-chqr linlinjava/litemall, bruteforce (Java): VulDB record, no fix commit.
- GHSA-7968-h4m4-ghm9 (CVE-2023-25156) Kiwi TCMS, bruteforce: the only fix (0ed213fa) is an nginx `limit_req` in etc/nginx.conf; no application code changed.
- GHSA-q373-f6gj-mw99 (CVE-2024-34451) Ghost, bruteforce (rate-limit bypass via X-Forwarded-For): disputed by the vendor, no fix.
- GHSA-x2f8-27qm-r3hf frappe/erpnext, limits (stock reservation beyond Sales Order limits): could not single out the fix among dozens of stock-reservation commits in the patched window; also a cross-order reference check (CWE-863).
- GHSA-9pvm-fcf6-9234 makeplane/plane, bruteforce (magic-code verify not rate limited): cited in public commit b1c78fe4 but the advisory is not published (404 as repo and global advisory), so not "disclosed".
- GHSA-fgrp-x4pm-v894 Ghost staff invitation concurrency: NVD duplicate of GHSA-vf9h-87xm-g767 (kept in cases_reserve.jsonl).
- vulnerability-lookup global advisory reference bef83724: note only, the case is kept with the correct fix c97aa9d5 (the referenced commit fixes a different finding, AUTH-VULN-01).

## Out of scope (language, library/framework, or not a business rule)

- GHSA-2h54-cprv-vj74 and GHSA-m75j-c5ff-9wh8 Hi.Events (hidden-ticket purchase, promo-code reservation): backend is PHP (Laravel).
- GHSA-pgcq-8grm-5rx9 Paymenter credit double-spend race: PHP.
- GHSA-78vr-q6cf-c7p6 Craft Commerce partial payment without lower bound; GHSA-pqq3-q84h-pj6x Sylius PayPal amount manipulation; GHSA-j67m-qx25-v22p Thelia; Bagisto/OpenMage/Snipe-IT/AVideo/MacCMS races: PHP.
- GHSA-xj3h-wwxq-gfcj Cloudreve storage-quota race; GHSA-j6gc-4893-qwmp new-api quota cache overwrite; GHSA-j95g-6g2h-3f33 ezBookkeeping TOTP reuse; Vikunja/SiYuan/JetKVM brute force: Go.
- PasswordPusher (view-limit race, brute force), Discourse 2FA rate limit, Rodauth OTP reuse: Ruby.
- FileRise TOTP replay / session-scoped TOTP limit (GHSA-9pg4-98cx-r82j, GHSA-4hfj-6478-5cv7): PHP.
- better-auth OAuth code / refresh rotation / rate limiter advisories (GHSA-7w99-5wm4-3g79, GHSA-392p-2q2v-4372, GHSA-p6v2-xcpg-h6xw, GHSA-44jh-23m7-hpcf): authentication library, not an application.
- GHSA-x2wq-9x2f-fhj7 Spring Security one-time token TOCTOU; GHSA-9hcr-9hcv-x6pv Flask-AppBuilder login rate limit; GHSA-gv85-wgxc-vc56 web2py; GHSA-vw39-2wj9-4q86 django-mfa2; GHSA-83r6-96m8-r52p Apache CXF refresh token; GHSA-cqmq-8755-7xvh Keystone negative take: framework/library internals.
- GHSA-48q9-3p26-8595 DNN captcha weakness: captcha image strength, not a business rule.
- GHSA-fpj4-9qhx-5m6m DNN force friend request acceptance; GHSA-fpr5-67pq-3hf5 DNN registration approval bypass; frappe/erpnext and Vendure cross-channel advisories: authorization/IDOR (other benchmark).
- GHSA-m2v3-fcjh-hm22 Kavita pre-auth account takeover: token validation flaw (authentication), not a business rule.
- GHSA-4jqc-cjj3-x26w Apache Roller WSSE capture-replay: protocol-level authentication (WSSE nonce), fix removes WSSE entirely.
- GHSA-c75c-5hc7-j4vp Rocket.Chat Apple Sign-In token replay: JWT claim validation (crypto/auth), not an app-level one-time token.
- GHSA-62mf-vhhw-xmf8 DNN site import from external source: SSRF-like.
- Sync-in GHSA-fgr8-f8r9-qh38 (WebDAV PUT bypasses storage quota), Outline GHSA-hqmp-r5jw-265r (attachment size limit / storage accounting), NocoDB GHSA-8rwr-f68v-cvw6 (attachment size limit): closer to resource limits / DoS than a business rule.
- GHSA-5m7p-wphr-xjp7 Postiz forged lifetime-deal codes: signature/verification weakness (crypto).
- Keycloak GHSA-f6r7-6w34-x2gp / GHSA-rr5q-3xwr-f323 (CWE-1284): LDAP OOM DoS and token-exchange size fallback (privilege), not a business limit.
- GHSA-xmmm-jw76-q7vg Keycloak OTP valid one extra period: OTP look-around window parameter; no commit reference; not pursued.
- openclaw webhook rate-limit advisories: agent gateway, mostly per-channel webhook secrets; not pursued.

## Valid but not pursued (class already covered, time)

- GHSA-35jj-42hp-8gmq n8n approval-gate bypass via reused resumeToken (workflow).
- GHSA-8r29-2mp2-pmrw Payload ecommerce plugin order confirmation validation (workflow).
- GHSA-qx5f-ghc2-7g5c Fides privacy-request identity verification bypass (workflow).
- GHSA-9w6g-7jpw-87hf CTFd activation and reset tokens interchangeable (workflow).
- GHSA-wj76-pcqr-mf9f / GHSA-xgvh-hg6v-gwjm Zulip invitation expiry / SSO skip (workflow).
- GHSA-9qwp-jf7p-vr7h / GHSA-ch7q-53v8-73pc authentik invitation reuse / expiry (workflow).
- GHSA-hwph-9537-mc3p / GHSA-6whj-8p3f-2xqp Saleor unbound email-change token / anonymous order merge (workflow).
- GHSA-x84p-6892-473c / GHSA-m6hq-f4w9-qrjj Weblate unverified API email change / invitation validation (workflow).
- GHSA-m6c7-4hc4-2gfq Mealie reset token without expiry check (workflow).
- GHSA-vwj8-4grf-3r8v Liferay reset tokens not invalidated after password change (replay; huge monorepo, two fix commits on different branches).
- GHSA-7xv9-wr46-j578 Zipline maxViews race; GHSA-7mf9-q77p-r4r3 / GHSA-mh65-9xcf-vf8v / GHSA-8m7c-hf24-5g47 NocoDB token races; GHSA-h3ww-q6xx-w7x3 Open WebUI first-user race; GHSA-r6wp-8gf8-82fx Weblate revoked-invitation race; GHSA-8647-755q-fw9p ajenti 2FA race; GHSA-2299-ghjr-6vjp / GHSA-w73w-g5xw-rwhf / GHSA-jpq4-7fmq-q5fj parse-server MFA races; GHSA-g495-58m2-7x67 pingvin-share-x admin race; GHSA-wgjv-p9mm-qw77 Zipline setup race (race).
- GHSA-7mqx-wwh4-f9fw / GHSA-24q2-59hm-rh9r Strapi rate limit; GHSA-wwrj-3hvj-prpm Misskey XFF rate limit; GHSA-hg56-r6hh-56j7 / GHSA-74jw-q47r-q5pv OpenCTI OTP / login brute force; GHSA-w5r6-mcgq-7pq4 / GHSA-6c5v-fxc6-8qgq Yamcs; GHSA-j6g5-p62x-58hw vantage6; GHSA-hv9p-2pqf-r5w3 pgAdmin; GHSA-m35c-r5p5-c3w8 Payload; GHSA-vxgr-w3f5-4g4j PLANKA TOTP; GHSA-5w5x-q9p5-9qg3 OctoPrint; rdiffweb rate limits (bruteforce).
- GHSA-g9fc-82c2-p2r6 Capgo exhausted credit grants keep plan valid; GHSA-9573-68xq-hwrx frappe/lms client-side quiz score (limits; Capgo logic is largely Supabase SQL).

## Keyed and verified, held out for balance (see cases_reserve.jsonl)

- GHSA-vf9h-87xm-g767 Ghost invite tokens usable multiple times (race): fine, held out because Ghost already had three cases and race had eight.
- GHSA-r3xq-68wh-gwvh parse-server reset-token race (race): fine, held out (parse-server already has a case; race over-filled).
- GHSA-xm43-3m56-w3wf Ghost paid gift memberships via donations (workflow): fine but its class is ambiguous (client-supplied checkout metadata injection) and its fix spans two commits.
