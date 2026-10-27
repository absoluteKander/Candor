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

Candor is a single-account IMAP/SMTP client (multi-account support is on the
roadmap, not yet built). It is organized as three parts that run together: a
background daemon that talks to your mail server and owns the local message
index, and a GTK4 graphical client that reads that index and talks to the
daemon for anything that needs to change. This split exists so the GUI can
feel instant — opening the app, switching folders, and marking things
read or starred never waits on the network, because those actions write to a
local SQLite index first and the daemon pushes the change to your server in
the background, usually within twenty seconds.

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

**Notifications.** A new, unread message arriving in your Inbox produces a
single desktop notification. Other folders don't notify — a new spam or
promotions message shouldn't interrupt you — and the very first sync of a
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
config file, never logged, and never held in a form that could end up in a
crash report or debug output.

**Local data is yours, and bounded.** The local message index and any
cached message text live in your own XDG data directory, never bundled or
sent anywhere beyond your mail server itself. What gets cached, and for how
long, follows a specific policy rather than growing without limit:
messages you've starred or sent are kept indexed for search permanently;
anything else you've simply opened is subject to a configurable age and
size cap, with the oldest entries evicted first once that cap is hit. You
control both limits, and the network check-in interval for folders other
than your Inbox, from Preferences.

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
against prior claims about the source: that no credentials, personal
information, or other secrets exist anywhere in the codebase; that no
dead or abandoned code remains from earlier approaches that were later
replaced; and, point by point, that every specific security claim made
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

- One email account at a time. Multi-account support is planned but not
  built.
- Linux only, and specifically GTK4/libadwaita — there's no packaging for
  any other platform.
- Plain text composing only; no rich-text or HTML authoring.
- The contacts autocomplete popover's on-screen behavior has had its
  underlying logic verified directly but has not been exercised through
  full interactive testing in every development environment this project
  has been built in.
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
