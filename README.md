# Candor

Candor is a native Linux email client built around one idea: your inbox is
sensitive, and the client reading it should treat it that way. It is a GTK4 /
libadwaita desktop application written in Rust, speaking IMAP and SMTP
directly to your mail provider, with no cloud component of its own.

This project was written entirely by Claude, an AI model made by Anthropic,
at the direction of Absolute-Candor, who specified the behavior, reviewed
the result, and made every product and security decision described below.
Where this document says "the code does X," that claim has been checked
against the actual source, not assumed from a comment or a design note. How
that checking was done, and what its limits are, is covered honestly in the
Testing and Verification section — please read that section before trusting
this software with anything sensitive.

## What Candor does

Candor is an IMAP/SMTP client. It is organized as three parts that run
together: a background daemon that talks to your mail server(s) and owns
the local message index, and a GTK4 graphical client that reads that index
and talks to the daemon for anything that needs to change. This split
exists so the GUI can feel instant — opening the app, switching folders,
and marking things read or starred never waits on the network, because
those actions write to a local SQLite index first and the daemon pushes
the change to your server in the background, usually within twenty
seconds.

**Reading mail.** Folders, read/unread state, starring, and the message list
all come from that local index, so browsing your mail is fast regardless of
connection quality. Opening a specific message does require a live fetch —
its content isn't pulled down until you actually ask to see it. Email
bodies are rendered as sanitized rich text, not raw HTML in an embedded
browser: there's no scripting, no live iframes, and remote images are
blocked by default, each replaced with a click-to-load placeholder so
opening a message never silently tells a sender you've read it.

**Organizing mail.** Archive, delete, move, star, and snooze all work the
way you'd expect from the message list or the open message, and update the
local index immediately. A "Load more" control fetches older messages past
the initial window when you need to see further back.

**Searching.** Typing in the search box filters instantly against what's
already indexed locally — subject, sender, and body text for any message
you've opened, starred, or sent. You can scope a search to the current
folder or every folder, and there's a separate, explicit "search the
server too" action for a live IMAP search when what you're looking for
hasn't been opened or cached locally yet.

**Composing.** New messages, replies, reply-all, and forwards are plain
text, with an optional signature appended automatically. An in-progress
message can be backed out of at any point and picks up again later as a
saved draft. Attaching a file to something you're sending is a normal file
picker action; Candor never auto-attaches anything from your own machine
without you choosing it.

**Multiple accounts.** Each account gets its own tab, the way a browser
handles multiple logins — not one combined inbox. There's no unifying your
mail across accounts, on purpose: the whole reason people keep separate
accounts is to keep them separate, and merging everything into one list
undermines that. Tabs have a fixed, explicit order you set once (never
by dragging them around live — a tab moving unexpectedly while you're
mid-use is exactly the kind of thing that leads to acting on the wrong
account), plus a color and a short name so which account you're looking
at is never ambiguous at a glance. One account is designated the default
Candor opens to; every other setting — signature, retention limits,
per-account color and order — lives in a single app-level Settings screen
rather than being duplicated across tabs.

**Setting up an account.** Candor tries, in order: a small built-in table
for a handful of major providers (Gmail, Outlook/Hotmail, Yahoo, Fastmail,
iCloud, Zoho); the provider's own self-hosted autoconfiguration file, the
same open standard Thunderbird uses; DNS records your domain may publish
for exactly this purpose; and finally a plain hostname guess, which is
only ever offered after a real connection to it actually succeeds. If none
of that works, you can enter server settings by hand. Candor deliberately
does not query any third-party lookup service to do this — every source
it checks is either built in or something you're already implicitly
trusting by using that email address. Candor never talks to a server
other than one you've explicitly identified as yours, for any reason.

Gmail, Yahoo, and iCloud all still accept a password for this — in
practice, a provider-issued app-specific password, since all three push
hard toward two-factor authentication on the account itself. Outlook.com
and Microsoft 365 are different: Microsoft is phasing out password-based
IMAP/SMTP login entirely, with no app-password fallback. For those
accounts, Candor signs you in through Microsoft's own OAuth2 flow
instead — it opens your system browser to a page served directly by
Microsoft, you approve it there, and Candor never sees or asks for your
actual password at any point. The resulting access is scoped narrowly to
mail (IMAP/SMTP), stored in your keyring the same way a password is, and
refreshed automatically in the background rather than asking you to sign
in again periodically.

Proton Mail doesn't fit this picture at all, by its own design: Proton
encrypts your mail so thoroughly that even Proton's own servers can't
read it, which means there's no plain IMAP server for any client —
Candor included — to just connect to. The only sanctioned way in is
Proton's own **Bridge** application, which you run locally; it decrypts
on your machine and exposes an ordinary local IMAP/SMTP server on
`127.0.0.1` with its own locally-generated password. From Candor's side,
that's just manual server entry pointed at `127.0.0.1` with whatever
password Bridge gave you — no special integration needed or built.

**Keeping the right account active.** Every account starts locked, and a
locked account cannot send mail — not from a disabled button alone, but
refused by the background daemon itself, so there's no path around it.
Unlocking is a single, deliberate click on that account's own tab, never
a keyboard shortcut, and it has no automatic timeout: once unlocked, an
account stays that way until you lock it again yourself. Composing,
replying, and forwarding are never blocked by this — you can read and draft
freely either way — only the actual send is gated. This exists for one
specific failure mode: stepping away from one account's tab, coming back
later, forgetting which one has focus, and sending something meant for one
address from another.

**Contacts.** Addresses you've actually typed into a new message or a
forward are remembered automatically for autocomplete the next time you
compose. Addresses you've only received mail from are not auto-added —
replying to someone doesn't put them in your contacts automatically, since
that would mean every mailing list or automated sender you've ever answered
ends up suggested forever. If you want to remember someone you received
mail from, there's a one-click "add to contacts" next to their name in the
reading pane — entirely optional, never required, never prompted for.
You can also import an existing contact list from a CSV export (Google,
Nextcloud, Outlook, and similar all support this); Candor does not connect
to any contacts service directly.

**Keyboard navigation.** Candor is built to be used entirely without a
mouse. Ctrl+1/2/3 move between the folder list, message list, and reading
pane; `j`/`k` move within whichever pane has focus; a consistent set of
single-letter actions (archive, delete, mark read/unread, star, reply,
reply-all, forward, schedule, move, select) act on whatever's focused.
Typing in any text field is never hijacked by these shortcuts.

**Notifications.** Only the default account can ever produce a real
desktop notification, and only for new mail in its actual Inbox — a new
spam or promotions message, or new mail on any other account, never
interrupts you at the OS level. Every account, including the default one,
also has a quiet in-tab indicator that lights up when it has unread mail
you haven't looked at yet; click it once to mute that account's
notifications entirely, a deliberate one-at-a-time action with no "mute
everything" shortcut. Clicking a desktop notification brings Candor to the
front and highlights the message in its list — it does not open the
message or mark it read on its own; whether it should also mark it read
is a separate, off-by-default Settings toggle. The very first sync of a
newly added account never fires a wall of notifications for mail that was
already there.

**Desktop integration.** On a system running Omarchy, Candor reads the same
theme palette your terminal and other themed apps use, so it matches your
accent color and light/dark setting automatically. This is entirely
optional and has no effect anywhere else.

## Security

Security in Candor is less about any single clever feature and more about
a small number of decisions applied consistently. The ones worth knowing:

**Attachments are never fetched or stored automatically.** This is the one
most worth understanding. Opening a message to read it never downloads any
attachment's content — not to display it, not to cache it, not even
temporarily to disk. The only way attachment content ever travels over the
network at all is a single explicit action: clicking to save an attachment,
which fetches it on demand and writes it only to the folder you choose.
Nothing is cached afterward. The reasoning is straightforward: an
attachment is the single most common way a malicious email actually does
damage, and "it downloaded automatically the moment I opened the message"
is not a sentence this project wants to be true. There is, deliberately,
no setting in the interface to turn this off. If automatic attachment
fetching is ever added for people who want it, it will be a configuration
file option only — never a toggle in the UI — specifically so that
turning it on is never the easy, accidental choice.

**Adding an account never phones home.** Finding the right IMAP/SMTP
settings for a new account (see "Setting up an account" above) deliberately
never queries a third-party lookup service the way some clients do — it
checks a small built-in table, the provider's own self-hosted
configuration file, your domain's own DNS, or a direct connection to a
guessed hostname, and nothing else. Candor never sends your email address,
or anything about you, to a server you haven't explicitly chosen to trust
by using that address in the first place.

**Sender authentication is checked and shown, not just assumed.** Every
opened message is checked for a valid DKIM signature (a real cryptographic
verification against the sending domain's public key, not merely a check
that a signature is present) and whether that signature's domain actually
matches the visible sender address — a message can be validly signed by an
unrelated domain while still spoofing the display name, and Candor checks
for that specifically. SPF and DMARC results are read from the
authentication headers your own mail provider already adds on delivery,
rather than re-verified independently, because a client has no reliable way
to independently confirm the originating server's identity after the fact.
This is summarized as a single Security indicator on each message, with
the full breakdown available on request — not twelve lines of acronyms
you're expected to interpret yourself.

**Links are checked before they're opened.** Clicking a link in a message
shows you exactly where it actually leads — with the real registrable
domain called out specifically, so a convincing look-alike subdomain can't
hide it — before handing off to your system browser. Candor never
navigates anywhere itself.

**Your password is never stored by Candor directly.** Account credentials
are handed to your desktop's own keyring service and never written to a
config file or logged — confirmed directly, not assumed: nothing in this
codebase prints, logs, or serializes a credential's actual value anywhere.
Memory holding one gets explicitly overwritten the moment it's no longer
needed, rather than just freed and left to linger until something else
happens to reuse that spot. What this doesn't claim is that a credential
can *never* end up in a crash dump — like any program that has to actually
authenticate over the network, there's a real moment where it sits in
plaintext in memory because that's what using it requires, and a crash at
exactly that instant would still capture it, the same as for any other
application. Candor doesn't currently do anything to disable or restrict
core dumps specifically, and this document isn't going to claim a
protection it doesn't actually have.

**Local data is yours, and bounded.** The local message index and any
cached message text live in your own XDG data directory, never bundled or
sent anywhere beyond your mail server itself. What gets cached, and for how
long, follows a specific policy rather than growing without limit:
messages you've starred or sent are kept indexed for search permanently;
anything else you've simply opened is subject to a configurable age and
size cap, with the oldest entries evicted first once that cap is hit. You
control both limits, and the network check-in interval for folders other
than your Inbox, from Settings.

**What "cached," "gone," and "gone but still cached" actually mean.** A
message is **cached** whenever Candor holds a local copy of its content —
either temporarily, because you opened it, or permanently, because you
starred it or sent it yourself. A message is **gone** once it no longer
exists on the server, for any reason: you deleted it, it was deleted
through your provider's webmail or another client, or a server-side
retention policy removed it — and once Candor confirms that, every local
cache for it is purged, including the "cached forever" search index,
because that permanence was a promise about a message that still exists,
not one meant to outlive it. "Delete" inside Candor specifically moves a
message to Trash, and Candor treats that as leaving the mailbox for good
the moment you click it — both caches are purged right away, not whenever
Trash eventually gets emptied on the server.

The one honest exception is **gone but still cached** — a brief, bounded
state, not a permanent one. Candor only learns a message is gone the next
time it actually checks that folder: near-instantly for your Inbox
(watched live via IMAP IDLE), but only on the polling interval you set in
Settings for every other folder (25 minutes by default). If a message
disappears from the server through some means other than clicking Delete
in Candor — expunged elsewhere, deleted via webmail, a provider-side
retention rule — it can still appear locally, cache and all, until that
next check runs. This window closes on its own and never persists past
the next sync of that folder.

**The architecture itself limits what can go wrong.** The GUI process never
writes to the local database directly — every change goes through the
background daemon, which is the only process that holds your credentials or
talks to your mail server. This isn't a security boundary against a
malicious actor (both processes run as you, on your own machine), but it
does mean there's exactly one place credential handling and network access
happen, rather than that logic being duplicated and potentially
inconsistent across the interface code.

## Testing and verification

Candor's test coverage has two layers. The first is conventional: unit
tests that exercise the local database layer against a real in-memory
SQLite database (covering, among other things, that a locally-queued
change can never be silently overwritten by a routine background sync — a
real bug class this kind of local-first app is specifically exposed to),
plus tests for CSV contact-import parsing and the DKIM/phishing-detection
logic, run with `cargo test` and passing as part of this project's normal
workflow. These tests are not a complete specification of the application
and were not written to hit a coverage number; they exist where a real,
specific failure mode was identified and worth guarding against directly.
A named subset of these specifically guard the security claims made
above as permanent regression tests, re-run before every release — see
[SECURITY.md](SECURITY.md) for exactly which tests, why each one exists,
and the standing methodology (including a dated log of full audit passes)
behind how these claims get checked and re-checked over time.

The second layer is live, manual, end-to-end verification against a real
mail account during development: actually opening messages, searching,
composing, archiving, and exercising the keyboard-only navigation path, with
screenshots taken at each step to confirm the interface did what it was
supposed to, rather than trusting that a change compiled cleanly and
therefore worked. This caught real bugs that a compiler and a unit test
suite would not have — among them, a case where closing a search box left
keyboard focus on the wrong control, so that a later keypress silently
re-opened the search box instead of doing what the user intended. It is
also, candidly, how two real mistakes happened during this same process:
typing a test phrase immediately after triggering an action that needed a
moment to complete, before confirming the interface had actually caught
up, which caused a couple of real emails in the test account to be
archived and starred unintentionally. Both were caught, traced to their
exact cause through the local database, and reverted. They're mentioned
here on purpose: a testing methodology that can produce visible, traceable
mistakes like this is one that's actually looking at what happened, not
one quietly assuming success.

Separately from ordinary development testing, this project went through a
dedicated security and code-quality review pass before this document was
written. That review checked, directly against the source rather than
against prior claims about the source: that no credentials or other
secrets exist anywhere in the codebase; that no dead or abandoned code
remains from earlier approaches that were later replaced; and, point by
point, that every specific security claim made
above actually holds in the code as written — including a full trace of
every code path that could conceivably touch attachment content, to
confirm the "never fetched or stored automatically" claim is true in every
case, not just the obvious one. That review found and fixed two cosmetic
issues (a leftover unused dependency and a stale comment) and one real
gap: a background process was relying on a check performed elsewhere in the
code instead of enforcing that check itself, which — while not exploitable
under this application's actual threat model of a single local user on
their own machine — was inconsistent with how every comparable check in the
codebase is otherwise enforced, and has been fixed to match.

**This review was performed entirely by Claude. There has been no
independent third-party security audit, no professional penetration test,
and no outside human reviewer of this code.** Absolute-Candor directed
every piece of this work, reviewed its results, and made every decision
about what to build and how — but the actual line-by-line verification
that the code does what it claims was AI-performed, not independently
verified by a second party. That is a meaningfully different, and weaker,
guarantee than a professional audit would provide. If you are evaluating
whether to trust Candor with real, sensitive email, that distinction should
weigh directly into that decision, and an independent review by a
qualified human auditor is a reasonable thing to want before relying on
this software for anything you can't afford to have go wrong.

## Current limitations

This is a working v1, not a finished product, and it's worth being direct
about what isn't done yet:

- Outlook/Microsoft OAuth2 sign-in has been verified live against a
  real Outlook account for reading mail — sign-in, token exchange,
  and IMAP access all genuinely work, watched working, not just
  compiled. Sending (SMTP) through the same flow has not been
  separately confirmed live: the one real account available to test it
  against ran into Microsoft disabling SMTP client authentication on
  that specific mailbox, a server-side restriction unrelated to this
  app's own code — the SMTP path uses the identical token and the
  equivalent authentication mechanism IMAP already proved works, but
  that's a structural argument, not a live confirmation, until it's
  been watched succeeding on an account that isn't restricted.
- Linux only, and specifically GTK4/libadwaita — there's no packaging for
  any other platform.
- Plain text composing only; no rich-text or HTML authoring.
- The contacts autocomplete popover's on-screen behavior, and the
  multi-account tab strip and Settings screen's own interactive controls
  (switching tabs by clicking, the lock and mute icons, the per-account
  Settings rows), have had their underlying logic verified directly —
  code review, and for several of them, triggering the exact same
  underlying action over D-Bus that a real click would — but have not
  been exercised through literal mouse-click testing in every development
  environment this project has been built in.
- There's no first-run explainer inside the app yet walking a new user
  through the caching and retention behavior described above — right now,
  this document is that explanation.

## License

Candor is licensed under the [PolyForm Noncommercial License
1.0.0](LICENSE) — free to use, study, and modify for any noncommercial
purpose, with attribution. It is not an OSI-approved open source license
(noncommercial restrictions are incompatible with the Open Source
Definition), and it is not free to use commercially. See the [LICENSE](LICENSE)
file for the full, binding terms; this paragraph is a summary, not a
substitute for reading it.
