"""Consumer-side corpus binding: does a witnessed journal describe THIS tree?

``receipt.release_chain`` proves custody of a journal — that the manifests are
hash-chained, canonically serialized, signed by a code-pinned producer key, and
witnessed by the consumer's configured RFC 3161 anchor set. It says nothing about
what the journal's rows *mean*.

This module supplies the missing half for a published rule corpus: the journal
rows enumerate content files by digest, and verification is a closed-world
comparison against the working tree. An unlisted file, a missing file, a
rewritten byte, a symlink where a regular file was recorded — each refuses.

A binding covers the bytes and the regular-file type, not the permission bits
— no row kind carries a mode, so a content file that gained the execute bit
after witnessing still matches its digest and still verifies here, while
release-object modes are covered separately by ``receipt verify --base-ref``,
which holds every release file present at that ref byte- and mode-identical.

Three row kinds, one journal:

``content``
    A file inside a consumer-declared content root, with a consumer-declared
    suffix. These are swept closed-world: the effective present set must equal
    the tree's set exactly, in both membership and digest. Membership is
    decided after folding — root and suffix alike are compared under Unicode
    NFC plus case folding — so neither a case- or normalization-varied
    spelling of a pinned suffix nor one of a pinned root can sit outside the
    closed world on a filesystem that treats it as the same file. A tree
    entry that aliases a root's own spelling is refused by name rather than
    merged, and an entry that is a symlink or any other reparse point is
    refused rather than followed — a junction is not a symlink on Windows,
    and descending one would sweep a directory outside the clone.

    Two spellings decide membership that no listing emits, so the sweep
    screens the names it is handed for both. A trailing dot or space is
    stripped by Win32 before a lookup, so the entry carrying it *is* the
    entry beside it. And an NTFS volume generating 8.3 short names gives a
    long name a second, addressable spelling whose extension may be a pinned
    suffix although the written one is not. That extension is modelled the
    way 8.3 generation derives it — spaces removed, leading periods removed,
    the text after the last remaining period mapped into the 8.3 character
    set and truncated to three — because deriving it from the written name
    instead read an embedded space as a character and let ``smuggled.y mlx``
    through while its alias ``SMUGGL~1.YML`` opened the same bytes (peer
    review, round seven). The stem is not modelled, nor is whether the
    volume generates short names at all; the extension is what decides
    membership.

    That model is bounded at both ends, because it was unsound at both.
    A character the 8.3 namespace cannot hold becomes an underscore — but
    the namespace is an OEM code page rather than ASCII, so which non-ASCII
    characters it *can* hold is the volume's decision and not this
    verifier's: with ``.éml`` pinned, ``smuggled.émlx`` is aliased ``.ÉML``
    on a code page 850 volume while the underscore model read ``._ML`` and
    skipped the file. So an extension carrying a non-ASCII character is
    refused as underivable rather than guessed at, and an alias-capable
    pinned content suffix must be ASCII. At the other end, an alias
    extension is at most three characters, so a pin longer than that cannot
    be carried by any alias; comparing the first three characters of a
    longer pin refused an ordinary ``notes.yam`` under a ``.yaml``
    configuration although no alias can end ``.yaml``. Only a pin an alias
    could carry is compared, and it is compared exactly (peer review, round
    eight).

    Both of those bounds are applied before the model is asked anything,
    because applying them afterwards refused names over questions nobody
    had put. The alias-capable pins are selected first, so a configuration
    pinning only ``.yaml`` derives no extension at all and ``notes.é`` is
    an ordinary non-content file rather than an underivable one; the
    extension source is truncated to three characters first, so the code
    page decides only about characters that reach the alias and ``x.ymlé``
    yields ``YML`` rather than a refusal; and the ASCII rule on a pin is
    asked only of pins an alias could carry, so ``.éyaml`` is a legal
    configuration and ``.éml`` is still refused (peer review, Sol round 2).

``attested``
    An exact path bound by digest without a sweep — the toolchain pin, the
    pinned validation workflow, an apply manifest. The consumer's spec names
    which paths it *requires*, so a producer cannot quietly drop one. The
    spelling is bound as well as the bytes: every component of every bound
    path must appear in a listing of its parent under exactly the declared
    spelling, so a case-insensitive volume resolving an attested
    ``readme.md`` to the ``README.md`` it stores is refused rather than
    hashed. Without that, the same corpus verified on the auditor who cloned
    onto APFS and refused as a missing file on the auditor who cloned onto
    ext4 (peer review, Sol round 2). Content files were already found by the
    spelled names the sweep enumerates; the walk asks it of them too, so one
    rule covers both kinds.
    Retiring one is recorded by a ``removed`` row, and the file has to leave
    the tree with it: a removed path still on disk refuses, whichever kind
    it was. Two questions are asked about a tombstone, in this order — does
    the host resolve the exact spelling, and does any fold-equal spelling
    survive in a listing — because a filesystem resolves names its own
    enumeration does not emit. A third spelling answers to neither
    question and is refused where the listing is read instead: a surviving
    ``retired/gone.`` or ``retired/gone `` is the tombstoned
    ``retired/gone`` on Win32, which strips a trailing dot or space before
    the lookup, while the exact ``lstat`` misses it on POSIX and its fold
    key differs from the tombstone's. Both askings screen for it, as the
    content sweep already does under a content root. The pair is asked twice
    per verification, for the reason the paragraph on pass order below
    gives, and the second asking shares no listing between one tombstone
    and the next, so a directory read for an earlier tombstone cannot
    answer for a later one. The second
    question walks the tree, so it is bounded: every entry taken from a
    listing and every candidate a search visits is charged against one budget
    for both askings together, and a listing wider than what is left of that
    budget is abandoned part-way — unread past the batch in hand — rather
    than fetched, sorted and indexed whole.

``gate``
    A declaration that some verification gate ran, carrying a reproducibility
    tier (axiom-encode#1192 requirement 6). This module validates the shape of
    the declaration and refuses an unpinned tier. It never re-executes a gate
    and never treats a declaration as evidence the gate passed. A caller that
    reports a ``restricted`` or ``ci-attested`` gate as "verified" is
    misreporting; :func:`verify_corpus_binding` returns the tiers separated so
    the distinction survives into the verdict.

Two of those lists are producer-controlled and rendered verbatim — the gate
declarations and the removed paths — so both are budgeted, and the budget is
the renderer's own arithmetic rather than a proxy for it. What one gate or
one removed path costs the verdict is derived from the object
``receipt.verify.result_to_dict`` builds and the
``json.dumps(..., indent=2, sort_keys=True)`` ``receipt.cli`` renders it
with: the escaped strings, and every brace, key, separator, indent and
newline JSON puts around them at that nesting depth. Charging a *floor* for
the structure instead let a journal filled to just under a cap render well
past it (peer review, round seven), so the constants are exact and a test
asserts equality between what is charged and the length of the section that
is rendered. Each is charged one item at a time and refused at the first
item that carries the running total over, so no journal makes the parser
account for more than the cap plus one item.

"Cap plus one item" is a bound on *validation work*, and it means that only
because the gate charges are made as the rows arrive. Summing after the
parse loop had finished bounded the verdict and nothing else: a 2,050-gate
journal reached the cardinality check with all 2,050 gates decoded and
validated, and a journal costing twice the text budget was validated in
full before the sum was compared (peer review, Sol round 2). Cardinality is
counted as the gate rows are met and refused at the declaration that would
be the cap plus one; the render cost is charged as each gate is validated
and refused at the first row carrying the total over. One gate's own
evidence is bounded by ``MAX_EVIDENCE_ENTRIES``, checked against the
mapping's length before any entry of it is validated. And decoding itself
is bounded a level above all three: ``MAX_JOURNAL_ROWS`` is checked by
counting line feeds before any row is parsed, so what a journal can make
this module allocate is a stated function of its stated size.

The order of the passes is itself load-bearing. Membership is swept, the
tombstones are looked for, the bound bytes are hashed, membership and per-file
identity are checked a second time, and the tombstones are looked for once
more. The two re-checks sit after the hashing and after the first tombstone
walk — the longest traversal here — so that both are inside the window they
close; a pass that ran between them and the return would be time in which the
tree could change with nothing left to notice.

The tombstone pass is the one that runs twice, and the second run caches
nothing whatever. It has to be that way twice over. The first run decides
absence from directory listings it caches and never re-reads, so a survivor
that appears after its parent has been listed is invisible to every later
search in that run — two tombstones sharing a parent is enough — and nothing
afterwards looked at a removed path at all: the re-checks close their window
over content and over the bound bytes, not over the paths the verdict calls
removed (peer review, round five). A second run that cached within itself
would then reproduce exactly that staleness one pass later, inside the pass
added to close it (peer review, round six), so every tombstone in it lists its
own directories. Both runs charge one budget, carried across, and a re-read is
charged like any other read, so re-establishing absence cannot buy the tree a
second walk's worth of budget.

Putting that run last used to cost a window: no membership re-sweep follows
it, so a content file inserted while it walked, or a bound file rewritten by
rename while it walked, was never looked at again. A third re-sweep would only
move that boundary, so the walk is watched by generation instead. Every
directory the closing membership sweep and that walk read is stamped — device,
inode, mtime, ctime — an instant before it is read, and every stamp is
re-stated after the walk has finished. An entry added, removed or renamed
moves its parent's mtime and ctime, so the change is refused although nothing
re-derived the set.

Stamping only what those passes read was not enough. Neither walk reaches the
directory that holds an attested file — attested paths sit outside the content
roots, and a tombstone walk descends only toward a removed path — so a journal
whose tombstones sit elsewhere, or carries none at all, left ``.axiom``
unstamped, and replacing ``.axiom/toolchain.toml`` by rename during the second
tombstone pass moved a generation nothing had recorded (peer review, round
seven). Every ancestor of
every bound path, from the tree root down to the file's own parent, is
therefore stamped as well, before the identity re-check re-states the files.

The per-file identity that re-check compares carries the file's own ctime for
the same reason the directory stamp does. Size and mtime are values a writer
restores with ``os.utime``; on POSIX the inode change time is not settable
from userspace at all, so a rewrite in place through the same inode is visible
even when everything else about the file has been put back.

What that check gives is a contract worth stating exactly, because the
obvious stronger one is false. The stamps are re-stated twice — forwards in
sorted order and then backwards — and a mismatch in either pass refuses. A
directory change is therefore detected if it lands before that directory's
final re-read. What remains is the span after each directory's last re-read,
which is not one instant: it is one instant for whichever directory is
re-read last and a little more for each of the others. Re-reading once, in
sorted order, made that span much longer than the module admitted — a writer
could change an already-re-read directory while a later one was still being
re-read, and nothing revisited it (peer review, round eight) — and no
re-read choreography removes the span, because some directory is always read
last. Only verifying an immutable snapshot the verifier holds open does, and
that is receipt#44 rather than anything shipped here.

Two narrower things sit inside that span as well: a rewrite in place through
the same inode after the identity re-check has already run, which moves the
file's own stamps and not its parent's and which nothing afterwards reads,
and a change on a filesystem whose directory timestamps are too coarse to
distinguish it from the stamp taken an instant earlier.

All of that rests on one platform property, so the platform is a
precondition rather than an assumption: ``st_ctime`` must be the inode
change time, which nothing in userspace can set. On Windows every supported
CPython reports the *creation* time there — 3.12 deprecated the field and
3.14 still fills it that way — so an entry could be added, removed or
renamed and the directory's mtime put back with ``os.utime``, leaving the
whole recorded tuple identical; the file ctime above is settable in the same
sense. :func:`verify_corpus_binding` therefore refuses at entry when
``os.name`` is not ``"posix"`` rather than reporting a verdict it cannot
support. Nothing platform-specific is attempted in its place: NTFS keeps a
real ChangeTime, but it is reachable only through ``ctypes`` and cannot be
exercised here, so reading it is a follow-up and not part of what ships.

The Windows *naming* rules this module implements are a separate matter and
they stay on. A trailing dot or space, and an 8.3 short-name alias, describe
spellings a corpus may carry and a consumer may one day resolve; they are
facts about the names in the tree, not about the host the verifier is
running on, and screening for them on POSIX is exactly the point.

A *declared* path spelled like a short name is refused outright, and what
counts as that spelling is the grammar 8.3 generation produces: one to six
characters from the short-name repertoire, a tilde, one to six digits, the
stem at most eight characters in all, then at most a three-character
extension. Accepting a tilde-digit anywhere in any run of non-period
characters was much wider, and it refused ``A~1B.TXT``, ``~1foo.txt`` and
``a ~1.txt`` — names no collision counter produces and a corpus may
legitimately hold (peer review, Sol round 2).

Every name this module folds is screened first against a *pinned* Unicode
repertoire, not the running interpreter's. Folding is only stable for
characters the standard has already encoded, so text carrying an unassigned
code point is refused — but asking the running table which those are made
the refusal itself version-dependent, and in the direction that matters:
U+A7CB is unassigned on Python 3.11 through 3.13 and assigned on 3.14, so
the same bytes were refused by one supported interpreter and accepted by the
next. The repertoire is therefore Unicode 14.0, the table the oldest
supported interpreter ships, carried as sorted ranges in
:mod:`receipt._unicode_repertoire`. Unicode never unassigns, so that set is
a superset of every later table's, and the stability policies fix folding and
normalization for everything 14.0 encoded: identical text is accepted or
refused identically on every supported interpreter (peer review, round
seven).

That screen is one function, ``_assert_foldable``, and the repertoire is
only the first of the questions it asks. The fold key is this module's
model of when two names are one name, and it is not a proof about the
filesystem a consumer will resolve the tree on. Two real filesystems
disagree with it in ways that open the closed world: HFS+ ignores
default-ignorable code points when it compares names, so ``evil.y\u200dml``
escapes a ``.yml`` sweep and a tombstone's fold bucket here while opening
``evil.yml`` there; and an upcase table built from Unicode's simple
uppercase mappings folds U+0131 DOTLESS SMALL I onto ``I``, so ``evıl.yml``
and ``evil.yml`` are one name under it and two under ``casefold`` (peer
review, round eight). Which table a given NTFS volume carries in
``$UpCase`` is not something a clone reports, and the two that can be read
disagree: Unicode 14.0 gives U+0131 the uppercase mapping U+0049, while
ntfs-3g's reconstruction of the Windows XP through 7 tables maps it to
itself. The dotted U+0130 is a different case and is no longer refused —
it is already uppercase, has no simple uppercase mapping, and neither
table maps it, so every source available agrees with the fold key about it
(peer review, Sol round 2). Neither of the two that remain is modelled,
because the module cannot know which filesystem is coming. Both are
refused, along with an unassigned code point and a Unicode format control,
by one screen run everywhere a name is folded — declared paths, the spec's
own roots and suffixes, the entry names the sweep judges, and the entry
names the tombstone search buckets — with a distinct message for each
class.

One more Win32 spelling is refused by that same screen, and it is not an
aliasing question at all. ``CON``, ``PRN``, ``AUX``, ``NUL`` and the
``COM``/``LPT`` series name character devices in every directory, whatever
extension follows them, so a journal and a POSIX file both spelling
``rules/NUL.yaml`` verified here while an ordinary Win32 open of that path
read the null device instead of the witnessed bytes (peer review, round
eight). The list is Microsoft's own, pinned in this module, matched per
component on the text before the first period and case-insensitively.

The same screen refuses a colon in any name it is handed, for a second
Win32 reason with the same shape. A declared path has refused one since
round three; an enumerated name had not, so a file emitted as
``rules/smuggled.yaml:payload.txt`` was skipped as non-content while a
Win32 open of it reads an alternate data stream of the bound
``rules/smuggled.yaml`` — a producer's bytes inside the tree and outside
the closed world (peer review, Sol round 2).

Every trust anchor arrives from the consumer's committed :class:`CorpusSpec`.
The module ships no defaults: not a content root, not a required gate, not an
accepted tier.
"""

from __future__ import annotations

import hashlib
import json
import json.encoder
import os
import pathlib
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

from receipt._unicode_repertoire import (
    FORMAT_CONTROL_RANGES,
    UNICODE_VERSION,
    is_default_ignorable,
    is_unassigned,
)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GATE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
#: The punctuation an 8.3 short name may carry unchanged. Everything outside
#: this set, the ASCII letters and the ASCII digits is replaced by an
#: underscore when Win32 derives a short name, which is what
#: :func:`_short_name_extension` models.
SHORT_NAME_PUNCTUATION = frozenset("$%'-_@~`!(){}^#&")
#: Every character an 8.3 short name may carry, which is that punctuation
#: plus the ASCII letters and digits. A character outside this set is one
#: 8.3 generation would have replaced, so a name carrying one is not a
#: generated short name.
SHORT_NAME_CHARACTERS = (
    frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    | SHORT_NAME_PUNCTUATION
)
#: The most characters an 8.3 short name's stem may carry, tilde and numeric
#: tail included. It is the ``8`` of 8.3, so it is a definition rather than a
#: choice: Microsoft's "Naming Files, Paths, and Namespaces" calls the alias
#: "the short MS-DOS (also called *8.3*) style naming convention".
SHORT_NAME_STEM_LIMIT = 8

CONTENT_KIND = "content"
ATTESTED_KIND = "attested"
GATE_KIND = "gate"
ROW_KINDS = frozenset({CONTENT_KIND, ATTESTED_KIND, GATE_KIND})

PRESENT = "present"
REMOVED = "removed"
FILE_STATES = frozenset({PRESENT, REMOVED})

PASS = "pass"
WAIVED = "waived"
#: A gate the pipeline was configured not to run. Recording it is mandatory:
#: a journal that simply omits a disabled gate reads identically to one where
#: the gate passed, which is the exact over-claim this schema exists to stop.
NOT_RUN = "not-run"
GATE_OUTCOMES = frozenset({PASS, WAIVED, NOT_RUN})

#: Reproducibility tiers, in descending order of what an outsider can check
#: alone. The consumer pins which of these its spec accepts; the package
#: asserts only that a tier outside this closed set is a hard refusal.
PUBLIC_TIER = "public"
RESTRICTED_TIER = "restricted"
CI_ATTESTED_TIER = "ci-attested"
GATE_TIERS = (PUBLIC_TIER, RESTRICTED_TIER, CI_ATTESTED_TIER)

#: Tiers an offline third party can re-establish without privileged inputs.
#: Exactly one, and naming it here keeps the honesty rule in one place.
INDEPENDENTLY_REPRODUCIBLE_TIERS = frozenset({PUBLIC_TIER})

#: The longest gate-evidence key or value the schema accepts. Sanitising
#: bounds what one character can do to a rendered verdict; nothing bounded how
#: many of them a producer may supply. A gate whose evidence carries two
#: hundred thousand blameless characters scrolls every line an auditor needed
#: to read out of the terminal, which defeats the verdict as surely as an
#: escape sequence would. A count of characters for the same reason
#: ``MAX_PATH_TEXT`` is one: this bounds what a refusal quotes.
MAX_EVIDENCE_TEXT = 1024
#: The most evidence entries one gate declaration may carry. The per-string
#: bound above caps each key and value; nothing capped how many pairs one
#: gate could hold, so a single legal gate row could carry an unbounded
#: number of short entries and every one of them was validated — screened
#: for size, for control characters, twice each — before the text budget
#: below was consulted at all (peer review, Sol round 2). Checked against
#: ``len(mapping)`` before the first entry is looked at, so the work one
#: gate can ask for is bounded by this rather than by the row's length.
#:
#: Sixty-four is generous for a real declaration, which names a command, a
#: workflow, a digest or two, and a reason.
MAX_EVIDENCE_ENTRIES = 64
#: The most characters of verdict text the effective view's gates may cost
#: in total. The per-string bound above caps one flood; a journal of a
#: thousand not-run gates each carrying a bound-length reason still put a
#: million characters into the verdict (peer review). Generous for any real
#: corpus, which declares tens of gates with digest-sized evidence.
#:
#: What is charged is what a gate costs the verdict, not what its producer
#: typed. Counting only gate-id and evidence payload characters let thirty
#: thousand gates carrying two characters of evidence each charge about a
#: quarter of a million and pass, while rendering four hundred thousand
#: characters of text and four million of JSON — the flood the constant
#: exists to stop, assembled out of strings none of which is long (peer
#: review, round five). So the fixed cost of the lines a gate produces is
#: charged alongside the characters it declares.
#:
#: And the characters it declares are counted as the verdict renders them,
#: not as Python holds them. ``json.dumps`` escapes with ``ensure_ascii``
#: on, so one character outside the BMP leaves as twelve; 249 four-character
#: evidence keys with 1024 of them per value is one legal gate charging
#: 262,013 and rendering 3,065,876 (peer review, round six). See
#: :func:`_rendered_length`.
#:
#: What is charged is now exactly what the JSON renderer emits for the
#: gates — every brace, key, separator, indent and newline of the section,
#: derived from the shape and pinned by a test — so this number is the size
#: of that section and not a proxy for it (peer review, round seven).
MAX_GATE_TEXT = 262144
#: The exact JSON structure one gate declaration costs the verdict, beyond
#: the escaped characters of its id and outcome and of its evidence.
#:
#: Derived from the shape ``receipt.verify.result_to_dict`` builds and the
#: ``json.dumps(..., indent=2, sort_keys=True)`` that ``receipt.cli`` renders
#: it with, not estimated: a gate is an object inside
#: ``gateDeclarations.byTier.<tier>``, so its members are indented ten spaces
#: and its evidence entries twelve. Counting from the newline that precedes
#: the object to the separator that follows it —
#:
#: * ``\n`` + eight spaces + ``{``                              = 10
#: * ``\n`` + ten spaces + ``"evidence": {``                    = 24
#: * ten spaces + ``}`` + ``,``                                 = 12
#: * ``\n`` + ten spaces + ``"gateId": `` + ``,``               = 22
#: * ``\n`` + ten spaces + ``"outcome": ``                      = 22
#: * ``\n`` + eight spaces + ``}`` + separator                  = 11
#:
#: — comes to 101. The last item of a list carries the newline before the
#: closing bracket where the others carry a comma, so the per-item cost is
#: the same wherever the gate sits.
#:
#: Charging a *floor* instead was the round-five decision, and it was wrong
#: in the direction that matters: 64 per gate and 24 per evidence entry
#: under-counted the structure by about half, so a journal filled to just
#: under the cap rendered well past it, and the test that was supposed to
#: hold the budget to the renderer permitted a ratio of four (peer review,
#: round seven). These constants are the renderer's own numbers now, and a
#: test asserts equality between what is charged and what is rendered, so a
#: change to either renderer fails a test rather than loosening a budget.
GATE_RENDER_STRUCTURE = 101
#: The same for one evidence entry, beyond its escaped key and value:
#: ``\n`` + twelve spaces + ``: `` + separator = 16. The schema requires a
#: non-empty evidence object, which is what makes this exact — an empty one
#: would render as ``{}`` and cost nothing per entry.
EVIDENCE_RENDER_STRUCTURE = 16
#: And one removed path, beyond its escaped string: ``\n`` + six spaces +
#: separator = 8. ``binding.removedPaths`` is a list of strings two levels
#: down, so its items are indented six. Charged before this round as the
#: escaped string alone, with the indentation, comma and newline free.
REMOVED_PATH_RENDER_STRUCTURE = 8
#: The most gate declarations one journal may carry. The text budget bounds
#: what a verdict renders; nothing bounded how many gates a producer could
#: put in front of an auditor, and cardinality is worth bounding for its own
#: sake — a verdict enumerating thousands of gates is unreadable however
#: short each line is, and no honest corpus declares them (peer review,
#: round five). Generous for any real one, which declares tens.
#:
#: Counted as the gate rows are met and refused at the declaration that
#: would be the cap plus one, *before* that row is validated. Comparing
#: ``len(gates)`` after the parse loop had finished meant a 2,050-gate
#: journal was decoded and validated in full — every gate id matched
#: against its pattern, every tier and outcome checked, every evidence
#: string screened twice — and only then refused for the count that was
#: knowable at row 2,049 (peer review, Sol round 2).
#:
#: Enforcing both budgets in row order makes something plain that checking
#: this one after the loop hid: it is a backstop and not a live limit. The
#: cheapest gate the schema admits — a one-character id, the shortest
#: outcome, one evidence entry with an empty key and an empty value —
#: costs 130 characters of rendered verdict once ``GATE_RENDER_STRUCTURE``
#: is charged exactly, which round seven made it, so 2,048 of them cost
#: 266,240 and ``MAX_GATE_TEXT`` refuses at about the 2,016th. No journal
#: can reach this cap. It is kept because it states a bound a reader can
#: check and because it would become live again if either of the other two
#: constants moved; a test pins the arithmetic so a change to either fails
#: a test rather than quietly reviving or burying it.
MAX_GATE_DECLARATIONS = 2048
#: The most rows one journal may carry, checked by counting line feeds
#: before any row is parsed. Every other budget here bounds what a *valid*
#: journal costs; this one bounds what an invalid one can make the parser
#: allocate before a single row has been decoded, so the memory a journal
#: can ask for is a stated function of its stated size.
#:
#: Derived rather than picked: the gate cap above is 2,048 declarations, and
#: the other three row kinds — content, attested and removed — get an equal
#: margin of 2,048 between them, which is 4,096. That margin is the number a
#: corpus with more bound files than it will have to raise, and it is stated
#: here rather than left implicit precisely so that raising it is a visible
#: change to a consumer-facing bound rather than a silent one.
MAX_JOURNAL_ROWS = 4096
#: The most characters one journal path may carry. Paths are quoted in
#: refusals and, for removed paths, rendered in the verdict; the bound is
#: checked before any other path rule so no refusal quotes a flood. A count
#: of characters, deliberately: what it bounds is the Python text a refusal
#: quotes back, not the JSON a verdict renders, and the total the verdict
#: renders is bounded by ``MAX_REMOVED_TEXT`` instead.
MAX_PATH_TEXT = 1024
#: The most characters the verdict's removedPaths may carry in total; the
#: gate budget's counterpart for the other producer-controlled list the
#: verdict renders verbatim (peer review, round two). Counted the same way
#: as the gate budget and for the same reason: a path of non-BMP characters
#: renders twelve times its length, so a set of them charged an eighth of
#: what the verdict would carry (peer review, round six). And with the same
#: correction: the eight characters of indentation, comma and newline the
#: renderer puts around each path are charged too, so this bounds the
#: section rather than the strings inside it (peer review, round seven).
MAX_REMOVED_TEXT = 262144
#: The most directory entries the whole tombstone pass may touch before it is
#: refused as unverifiable rather than allowed to run on. Counted in entries
#: rather than listings, and once for the pass rather than once per removed
#: path: a per-path listing budget bounded each search while leaving the pass
#: itself quadratic, so R tombstones against a root of E entries cost R×E with
#: nothing to stop it (peer review, round three). The index below reads each
#: directory once and shares it across every removed path, so the real cost is
#: the tree, and this bounds that.
#:
#: An entry is charged when it is taken from a listing and again each time a
#: search visits it as a candidate, because both are work and neither was
#: bounded by counting listings alone: the whole of an arbitrarily wide
#: directory was sorted and indexed before anything checked the budget, and a
#: cached fold-collision bucket was re-traversed by every tombstone for free
#: (peer review, round four). The listing is fetched in batches and abandoned
#: where the charge refuses, so the count bounds the directory read as well
#: as the work done with what it named (peer review, round five). The two
#: tombstone passes share the total: the second index is constructed with
#: what the first one spent, so the pass that re-establishes absence cannot
#: buy the tree a second walk's worth of budget. That second pass shares no
#: listing between one tombstone and the next (peer review, round six), so it
#: costs more than the first — a directory on the path of R removed paths is
#: read R times rather than once — and every one of those reads is charged
#: here, which is the point: a re-read is work, and the cap is on work.
MAX_TOMBSTONE_WORK = 262144
#: The most characters a refusal quotes of a producer-controlled value.
MAX_QUOTED_TEXT = 256

_ROW_KEYS: dict[str, frozenset[str]] = {
    CONTENT_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "path", "sha256", "state"}
    ),
    ATTESTED_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "path", "sha256", "state"}
    ),
    GATE_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "gateId", "tier", "outcome", "evidence"}
    ),
}


class CorpusError(ValueError):
    """The journal is malformed, or it does not describe this working tree."""


@dataclass(frozen=True)
class CorpusSpec:
    """Corpus-specific binding constants, pinned in the consumer's code.

    The producer chooses what to write into the journal. The consumer chooses
    what the journal must cover before a verdict is allowed to pass. Every
    field here is the second kind of choice, which is why none of them have
    package defaults.
    """

    schema_version: str
    content_roots: tuple[pathlib.PurePosixPath, ...]
    content_suffixes: tuple[str, ...]
    required_attested_paths: frozenset[str]
    accepted_gate_tiers: frozenset[str]
    required_gates: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or not self.schema_version:
            raise CorpusError("CorpusSpec schema_version must be a non-empty string")
        if type(self.content_roots) is not tuple or not self.content_roots:
            raise CorpusError("CorpusSpec must declare at least one content root")
        for root in self.content_roots:
            if not isinstance(root, pathlib.PurePosixPath):
                raise CorpusError("CorpusSpec content_roots must be PurePosixPath")
            # The spec's own two fold inputs are screened here, before the
            # path rules, so a refusal names the committed spec that carries
            # the fault rather than a path. A root also reaches
            # _validate_relative_path below, which screens it again; a suffix
            # reached nothing, which is the hole (see the suffix loop).
            for component in root.as_posix().split("/"):
                _assert_foldable(component, "CorpusSpec content root")
            _validate_relative_path(root.as_posix(), "content root")
        if type(self.content_suffixes) is not tuple or not self.content_suffixes:
            raise CorpusError("CorpusSpec must declare at least one content suffix")
        for suffix in self.content_suffixes:
            if type(suffix) is not str or not suffix.startswith("."):
                raise CorpusError(
                    f"CorpusSpec content suffix must start with '.': {_quoted(suffix)}"
                )
            # A suffix was checked for its leading dot and nothing else, while
            # _has_pinned_suffix folds it against every path in the tree and
            # against every entry name the sweep sees. An unassigned code
            # point in one folds differently under each supported table, so
            # which files the closed world contained depended on the
            # verifier's interpreter — the same defect _assert_foldable closes
            # everywhere else this module folds (peer review, round four).
            _assert_foldable(suffix, "CorpusSpec content suffix")
            # And ASCII, because the 8.3 screen below cannot derive an alias
            # extension for a non-ASCII one: which characters survive into a
            # short name is the volume's OEM code page's decision, and an
            # auditor's clone does not report it. A pin the screen cannot
            # judge against would leave the sweep unable to answer the
            # question the pin exists to ask (peer review, round eight).
            #
            # Asked of alias-capable pins only, for the reason
            # _short_name_carries_pinned_suffix gives: an extension of more
            # than three characters is carried by no alias, so ".éyaml" asks
            # the screen nothing and refusing it refused a legal
            # configuration over a question that is never put (peer review,
            # Sol round 2). ".éml" is still refused, because that one is a
            # pin an alias could carry and the derivation cannot be made.
            if len(suffix) <= 4 and any(ord(character) > 0x7F for character in suffix):
                raise CorpusError(
                    "CorpusSpec content suffix must be ASCII, because an 8.3 "
                    "alias extension cannot be derived against a non-ASCII "
                    f"one: {_quoted(suffix)}"
                )
        if type(self.required_attested_paths) is not frozenset:
            raise CorpusError("CorpusSpec required_attested_paths must be a frozenset")
        for path in sorted(self.required_attested_paths):
            _validate_relative_path(path, "required attested path")
        if type(self.accepted_gate_tiers) is not frozenset:
            raise CorpusError("CorpusSpec accepted_gate_tiers must be a frozenset")
        unknown = sorted(self.accepted_gate_tiers - set(GATE_TIERS))
        if unknown:
            raise CorpusError(
                "CorpusSpec accepts unknown reproducibility tier "
                f"{_quoted(unknown[0])}; "
                f"known tiers are {', '.join(GATE_TIERS)}"
            )
        if type(self.required_gates) is not frozenset:
            raise CorpusError("CorpusSpec required_gates must be a frozenset")
        for gate_id in sorted(self.required_gates):
            if GATE_ID_RE.fullmatch(gate_id) is None:
                raise CorpusError(
                    f"CorpusSpec required gate id is malformed: {_quoted(gate_id)}"
                )

    def content_root_of(self, path: str) -> pathlib.PurePosixPath | None:
        """The pinned root this path sits under, compared by fold key.

        Byte-exact membership contradicted the rest of the module. The suffix
        predicate folds, the alias guard folds, and the tombstone search
        folds — but a path's *root* was matched byte for byte, so on a
        case-sensitive host "RULES/evil.yaml" sat outside the pinned "rules/"
        root, was not content, and was never swept; on a case-insensitive
        host the same bytes are inside it. Which host the auditor cloned onto
        decided whether the closed world contained the file (peer review,
        round three). Folded, both hosts agree it is content, and the tree
        walk below refuses the aliasing spelling outright.
        """

        folded = _path_fold(path)
        for root in self.content_roots:
            if folded.startswith(_path_fold(root.as_posix()) + "/"):
                return root
        return None

    def is_content_path(self, path: str) -> bool:
        if self.content_root_of(path) is None:
            return False
        return _has_pinned_suffix(path, self.content_suffixes)


@dataclass(frozen=True)
class FileBinding:
    path: str
    sha256: str
    entry_index: int


@dataclass(frozen=True)
class GateDeclaration:
    """One gate the producer declares ran, with its reproducibility tier.

    This is a *declaration*, not a verification. ``tier`` states what an
    outsider could do about it: re-run it (``public``), re-run it only with
    inputs they may not have (``restricted``), or nothing but trust CI's
    identity (``ci-attested``).
    """

    gate_id: str
    tier: str
    outcome: str
    evidence: Mapping[str, str]
    entry_index: int

    @property
    def independently_reproducible(self) -> bool:
        return self.tier in INDEPENDENTLY_REPRODUCIBLE_TIERS


@dataclass(frozen=True)
class CorpusVerification:
    """What the journal binds, after it has been proved to match the tree."""

    content: tuple[FileBinding, ...]
    attested: tuple[FileBinding, ...]
    gates: tuple[GateDeclaration, ...]
    removed_paths: tuple[str, ...]

    def gates_in_tier(self, tier: str) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if gate.tier == tier)

    @property
    def reproducible_gates(self) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if gate.independently_reproducible)

    @property
    def unreproducible_gates(self) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if not gate.independently_reproducible)


def _quoted(value: Any) -> str:
    """repr of a producer-controlled value, truncated so a refusal is bounded.

    Every value a refusal quotes goes through here, not only the two that
    started it. A refusal is rendered into the verdict an auditor reads, and
    the schema bounds only some of the strings a producer can put in one: a
    row's ``kind``, ``schemaVersion``, ``entryIndex``, ``tier``, ``outcome``,
    ``sha256`` and ``state``, and the unknown-key list, were all reproduced
    verbatim, so a million-character tier scrolled the verdict away exactly
    as an oversized evidence string would have (peer review, round three).
    A path is bounded at ``MAX_PATH_TEXT``, which is still four times what
    belongs on a line.

    Under the bound this is plain ``repr``, so it changes no refusal a real
    corpus can produce — and ``repr`` is also what escapes a control character
    a filesystem name may carry, which is why tree-derived paths come through
    here too.
    """

    text = repr(value)
    if len(text) <= MAX_QUOTED_TEXT:
        return text
    return f"{text[:MAX_QUOTED_TEXT]}…[{len(text) - MAX_QUOTED_TEXT} more characters]"


def _is_format_control(code: int, category: str) -> bool:
    """Whether this code point is a Unicode format control on any pinned table.

    The pinned Unicode 16.0 ``Cf`` set lives in
    :data:`receipt._unicode_repertoire.FORMAT_CONTROL_RANGES` — it moved
    there so ``receipt.cli`` can escape the same set on its way to a
    terminal — and the running interpreter's own answer widens it, never
    narrows it.
    """

    if category == "Cf":
        return True
    return any(low <= code <= high for low, high in FORMAT_CONTROL_RANGES)


def _reject_control_characters(value: str, label: str) -> str:
    """Refuse control, format, and line-separator code points in producer text.

    Every string in this schema is written by a producer and later rendered to
    a terminal. A carriage return, an ESC, or a line feed inside one lets the
    producer redraw the verdict: a witnessed "reason" carrying
    ``\\x1b[2K\\r  VERDICT: PASS`` overwrites the line that was about to say the
    gate did not run. The verdict is the product here, so the sanitising
    belongs at the schema boundary where the text enters, not only at the
    point where it is printed. (Found by cross-family review.)

    The C0 block is not the only way to do it, so two more classes refuse
    here:

    - Every code point in Unicode category Cf, as of Unicode 16.0 and pinned
      in :data:`receipt._unicode_repertoire.FORMAT_CONTROL_RANGES`, or in
      the running interpreter's own table. These render as nothing while
      changing what the reader sees: U+202E RIGHT-TO-LEFT OVERRIDE reverses
      the remainder of the line, so a gate declared not-run can be spelled to
      read as passed, and U+200B lets two evidence keys print identically.
    - U+2028 and U+2029, line separators outside the C0 block, which split one
      evidence string into as many verdict lines as the producer wants in any
      renderer that honours them.
    - Every code point in category Cs, a lone surrogate. JSON spells one as
      ``\\ud800`` inside otherwise valid UTF-8, so it survives the decode; no
      filesystem call accepts it (``os.lstat`` raises ``UnicodeEncodeError``,
      a ``ValueError`` no ``OSError`` handler sees); and no legitimate path or
      reason carries one.

    Taking the Cf class whole has a cost, accepted deliberately: U+200C and
    U+200D are required spelling in Persian, Hindi and Sinhala, and U+061C
    appears in ordinary Arabic text, so a rule file named in those scripts,
    or a not-run reason written in them, refuses here. The verdict quotes
    these strings to a reader, and a reader cannot tell apart two spellings
    that differ only in an invisible code point; a narrower list would have
    to be maintained against exactly that threat. Refusing is the fail-closed
    side, and the refusal names the code point so the cause is legible.
    """

    for character in value:
        code = ord(character)
        category = unicodedata.category(character)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise CorpusError(
                f"{label} contains a control character ({code:#04x}): {_quoted(value)}"
            )
        if _is_format_control(code, category):
            raise CorpusError(
                f"{label} contains a Unicode format control "
                f"({code:#04x}): {_quoted(value)}"
            )
        if category == "Cs":
            raise CorpusError(
                f"{label} contains a lone surrogate ({code:#04x}): {_quoted(value)}"
            )
        if code in (0x2028, 0x2029):
            raise CorpusError(
                f"{label} contains a Unicode line separator "
                f"({code:#04x}): {_quoted(value)}"
            )
    return value


def _rendered_length(text: str) -> int:
    """What one producer string costs the verdict once JSON has escaped it.

    The budgets below bound what a verdict renders, and the verdict is
    rendered by ``json.dumps(..., indent=2, sort_keys=True)`` in
    ``receipt.cli`` — with ``ensure_ascii`` left at its default of True. So
    every non-ASCII character a producer writes leaves this module as an
    escape: three ASCII characters become six for a BMP character, and a
    character outside the BMP becomes a surrogate pair spelled as twelve
    (peer review, round six). Charging Python characters let one legal gate
    with 249 four-character keys and 1024 U+1F600 characters per value charge
    262,013 against a budget of 262,144 and render 3,065,876 characters of
    JSON — the flood the budget exists to stop, a factor of twelve under the
    cap.

    So the charge is what ``json.dumps`` makes of the string, quotes
    included — taken from the escaper ``json.dumps`` applies to a string
    rather than by calling it. ``JSONEncoder.encode`` short-circuits a
    top-level string to exactly this function when ``ensure_ascii`` is on, so
    the two are equal by construction and a test pins the equality; naming
    the escaper keeps a caller who has substituted something for
    ``json.dumps`` from silently changing what a budget charges.

    The per-string bounds (``MAX_EVIDENCE_TEXT``, ``MAX_PATH_TEXT``) stay
    counts of characters, because what they bound is what a *refusal* quotes
    back, which is Python text and not JSON.
    """

    return len(json.encoder.encode_basestring_ascii(text))


def _reject_oversized_text(value: str, label: str) -> str:
    """Refuse producer text too long to belong in a verdict a human reads.

    Checked before the character screen, deliberately: that screen quotes the
    offending value back, so refusing a two-hundred-thousand-character string
    there would emit the flood it exists to prevent. This message carries the
    length instead of the text.
    """

    if len(value) > MAX_EVIDENCE_TEXT:
        raise CorpusError(
            f"{label} is longer than {MAX_EVIDENCE_TEXT} characters: "
            f"{len(value)} characters"
        )
    return value


def _assert_assigned(value: str, label: str) -> str:
    """Refuse text carrying a code point outside the pinned Unicode repertoire.

    The fold key (see :func:`_path_fold`) is only stable across Unicode tables
    for assigned characters: the standard's stability policies fix case
    folding and normalization once a character is encoded, and say nothing
    before. An unassigned code point folded one way on Unicode 15 and another
    on 16 (U+10D50, peer review), so text carrying one could alias under one
    interpreter and not another.

    Declared paths were screened here from the start. Filesystem entry names
    were not, and they are folded by the sweep, by the suffix predicate, and
    by the tombstone search — U+A7CB folds to U+0264 on Unicode 16 and to
    itself before it, so which files a closed-world sweep considers the same
    file depended on the verifier's interpreter (peer review, round three).
    Every name this module folds passes through here first.

    Which table decides that is now pinned rather than inherited. Asking the
    *running* interpreter left the screen with the defect it exists to close,
    facing the other way: U+A7CB is ``Cn`` on 3.11 through 3.13 and assigned
    on 3.14, so the same bytes were refused by one supported interpreter and
    accepted by the next, and the acceptance the screen promises to make
    stable was itself version-dependent (peer review, round seven). The
    repertoire is Unicode 14.0, the table the oldest supported interpreter
    ships; :mod:`receipt._unicode_repertoire` carries it and says why that
    direction is the safe one — Unicode never unassigns, so the pinned set is
    a superset of every later table's, and the stability policies fix folding
    and normalization for everything 14.0 assigned. Identical text is
    therefore accepted or refused identically from 3.11 onward.
    """

    for character in value:
        code = ord(character)
        if is_unassigned(code):
            raise CorpusError(
                f"{label} contains a code point outside the pinned Unicode "
                f"{UNICODE_VERSION} repertoire ({code:#06x}): {_quoted(value)}"
            )
    return value


#: The basenames Win32 resolves to a character device instead of to a file,
#: in every directory and whatever extension follows them: ``rules/NUL.yaml``
#: opens the null device, not the bytes a journal bound. Pinned here rather
#: than derived, because it is a Win32 fact and not a Unicode one, and every
#: entry is attributed to the source it rests on rather than to a union of
#: sources that disagree.
#:
#: Microsoft, "Naming Files, Paths, and Namespaces",
#: learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file, fetched
#: 2026-09-03 with the page and its docs source both dated 2024-08-28:
#:
#:     Do not use the following reserved names for the name of a file:
#:     CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8,
#:     COM9, COM¹, COM², COM³, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7,
#:     LPT8, LPT9, LPT¹, LPT², and LPT³. Also avoid these names followed
#:     immediately by an extension; for example, NUL.txt and NUL.tar.gz are
#:     both equivalent to NUL.
#:
#: That sentence is the source of every entry below except the two named
#: next, and of the superscripts in particular, which the same page's note
#: says Windows "treats [...] as valid parts of COM# and LPT# device names,
#: making them reserved in every directory".
#:
#: CONIN$ and CONOUT$ rest on ``ntdll``'s own matcher instead:
#: ``RtlIsDosDeviceName_U`` resolves both, and Microsoft's page does not
#: list them. What was read is Wine's implementation of that function
#: (dlls/ntdll/path.c, fetched 2026-09-03), which carries a conformance
#: table run against real Windows.
#:
#: COM0 and LPT0 were in this table and are not any more, because neither
#: source supports them. The sentence above lists COM1 through COM9, and
#: that matcher's digit test is ``if (*end <= '0' || *end > '9') break;``,
#: so a zero is not a device there either. The entry was kept as the
#: fail-closed side of a disagreement that does not exist, and its cost is
#: real: a corpus holding an ordinary ``COM0.yaml`` was refused outright
#: (peer review, Sol round 2).
WIN32_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in range(1, 10)}
    | {f"LPT{digit}" for digit in range(1, 10)}
    | {f"COM{superscript}" for superscript in "\u00b9\u00b2\u00b3"}
    | {f"LPT{superscript}" for superscript in "\u00b9\u00b2\u00b3"}
    # ntdll's RtlIsDosDeviceName_U, not Microsoft's page.
    | {"CONIN$", "CONOUT$"}
)


def _ascii_upper(text: str) -> str:
    """Uppercase the ASCII letters and nothing else.

    ``str.upper`` applies the full Unicode case mapping, which folds
    characters this comparison has no business folding — U+0131 uppercases
    to ``I`` and the ligature ``ﬀ`` to ``FF`` — while Win32's device-name
    match is over the ASCII spellings. The superscript digits in
    :data:`WIN32_RESERVED_DEVICE_NAMES` are compared as they are written,
    which is what makes them entries in the table rather than a mapping.
    """

    return "".join(
        chr(ord(character) - 32) if "a" <= character <= "z" else character
        for character in text
    )


def _win32_device_basename(component: str) -> str:
    """What Win32 compares against its device table, for one path component.

    Two rules, in this order, because the order is what decides the answer.
    The component is truncated at its first period *or colon*, and only then
    are trailing spaces removed from what is left. So ``NUL.yaml``,
    ``NUL .yaml``, ``nul  ....``, ``NUL:stream`` and a bare ``nul`` all
    present ``NUL`` to the table.

    Taking the text before the first period and nothing else was not enough,
    and the module already held both halves of the rule without composing
    them: :func:`_strips_to_another_name` exists because Win32 strips
    trailing spaces, but it only fires when the space is at the end of the
    *component*, and ``NUL .yaml`` ends in ``l``. One space was therefore
    enough to walk a bound path past the device screen (peer review, round
    eight). The composition here is ``ntdll``'s ``RtlIsDosDeviceName_U``,
    which truncates at ``.`` or ``:`` and then removes trailing spaces
    before it matches.

    Leading spaces are *not* removed, because that matcher does not remove
    them: `` NUL.yaml`` is an ordinary name on Win32 and is one here.
    """

    head = component
    for index, character in enumerate(component):
        if character in ".:":
            head = component[:index]
            break
    return _ascii_upper(head.rstrip(" "))


#: The Turkic dotless small i. Unicode gives it the simple uppercase mapping
#: U+0049 — ``0131;LATIN SMALL LETTER DOTLESS I;Ll;0;L;;;;;N;;;0049;;0049``
#: in Unicode 14.0's ``UnicodeData.txt`` — so an upcase table built from
#: those mappings folds ``evıl.yml`` and ``evil.yml`` together, while
#: ``str.casefold`` and this module's fold key keep them apart. Refused by
#: :func:`_assert_foldable` rather than modelled, for the reason stated
#: there.
#:
#: Its dotted counterpart U+0130 was here and is not any more. It is already
#: uppercase, it has *no* simple uppercase mapping —
#: ``0130;LATIN CAPITAL LETTER I WITH DOT ABOVE;Lu;0;L;0049 0307;;;;N;LATIN
#: CAPITAL LETTER I DOT;;;0069;``, an empty field 12 — and no upcase table
#: this module could read maps it onto ``I``. It was refused on the premise
#: that NTFS folds it there, which the sources do not support (peer review,
#: Sol round 2). What ``casefold`` does to it — the two-character key
#: ``i\u0307`` — merges it with a sequence a real table keeps apart, which
#: is over-refusal rather than under-refusal, and
#: :func:`_reject_aliasing_paths` already answers that.
TURKIC_DOTLESS_I = "\u0131"


def _assert_foldable(value: str, label: str) -> str:
    """Refuse a name whose equivalence class this module cannot compute.

    One screen, run everywhere this module folds a name: declared paths, the
    spec's own roots and suffixes, the tree entry names the closed-world
    sweep judges, and the entry names the tombstone search buckets. What it
    asks is not "is this name legal" but "does :func:`_path_fold` decide the
    same question a real filesystem will decide". Where the answer is no, the
    name is refused.

    Refusal is the honest answer here because the alternative is to model a
    filesystem this module cannot identify. A verifier runs on the auditor's
    clone; the tree may be resolved later on APFS, HFS+, ext4, NTFS or
    something else, and each has its own idea of when two names are one
    name. The fold key is one such idea — NFC plus case folding — and it is
    the one every other check in this module is built on. A name whose
    equivalence class differs between that key and a real filesystem is a
    name the closed world cannot be closed over: the sweep and the tombstone
    search would put it in one bucket and the filesystem in another, so
    "these are exactly the files" would be false on the host that matters
    without being false on the host that checked (peer review, round eight).

    Six refusals, each with its own message, each checked over the whole
    string before the next one is asked — so which class a name is refused
    under is a property of the name and not of where in it the offending
    character sits. The first four are about single code points:

    - a code point outside the pinned Unicode 14.0 repertoire, which is
      :func:`_assert_assigned` and the oldest of the four;
    - a Unicode format control. This is the ``Cf`` screen
      :func:`_reject_control_characters` has always applied to *producer*
      text, now applied to filesystem names as well. Asked before the
      default-ignorable question although the two sets overlap heavily,
      because a format control is refused for two independent reasons — it
      changes what a reader sees and it may be ignored by a name comparison
      — and this is the message a declared path carrying one already gets,
      so U+200D reads the same wherever it turns up;
    - a default-ignorable code point. HFS+ ignores these when it compares
      names, so ``evil.y\u200dml`` and ``evil.yml`` are one file there: the
      first escapes a ``.yml`` sweep and a tombstone's fold bucket here
      while opening the second one there. The table is Unicode 14.0's, in
      :mod:`receipt._unicode_repertoire`;
    - U+0131, the Turkic dotless small i. Unicode gives it the simple
      uppercase mapping U+0049, so an upcase table built from those
      mappings — which is what ``str.upper`` implements, and what an NTFS
      volume's ``$UpCase`` may carry — folds ``evıl.yml`` and
      ``evil.yml`` together, while ``casefold`` and this fold key keep them
      apart. That is the unsafe direction: two names this module calls
      distinct are one file there. Refusing it is the only answer that does
      not require choosing whose case-folding this module implements,
      because adopting the mapping would break every POSIX host that holds
      the two names apart. Its dotted counterpart U+0130 is *not* refused:
      it is already uppercase, has no simple uppercase mapping at all, and
      no readable upcase table maps it onto ``I``, so the premise it was
      refused on was wrong (peer review, Sol round 2).

    The fifth is about a whole component rather than a character in one: a
    Win32 reserved device name. ``CON``, ``PRN``, ``AUX``, ``NUL``, the
    ``COM`` and ``LPT`` series and their superscript spellings resolve to a
    character device in every directory and whatever extension follows
    them, so an ordinary Win32 open of ``rules/NUL.yaml`` reads the null
    device rather than the bytes a journal bound and a digest witnessed
    (peer review, round eight). This is not an aliasing question — the name
    does not resolve to some *other* file — but it has the same shape and
    the same answer: the spelling means one thing to this verifier and
    another to the host that will use it. What is matched against
    :data:`WIN32_RESERVED_DEVICE_NAMES` is what Win32's own matcher
    compares, which :func:`_win32_device_basename` derives — the text
    before the first period or colon, with trailing spaces then removed —
    because taking the text before the first period alone let ``NUL .yaml``
    through.

    The sixth is a colon, and it is the same kind of fact: Win32 reads one
    as a stream or a drive separator rather than as a character in a name.
    A declared path has refused a colon since round three, and an
    *enumerated* name did not, so ``rules/smuggled.yaml:payload.txt`` passed
    every screen and was skipped as non-content — while a Win32 open of it
    reads an alternate data stream of ``rules/smuggled.yaml``, a bound file,
    and a producer's bytes ride into the tree beside witnessed ones without
    appearing anywhere in the closed world (peer review, Sol round 2). It is
    asked last so that a device name carrying a colon keeps the more
    specific message, since Win32's matcher truncates at the colon and
    resolves ``CON:stream.yml`` to the console.

    ``value`` may be a whole relative path or a single component; every
    message quotes it whole through :func:`_quoted`, so a refusal names what
    was screened. The component split is over ``/``, so a value that is
    already one component is screened as one.
    """

    _assert_assigned(value, label)
    for character in value:
        code = ord(character)
        if _is_format_control(code, unicodedata.category(character)):
            raise CorpusError(
                f"{label} contains a Unicode format control "
                f"({code:#04x}): {_quoted(value)}"
            )
    for character in value:
        if is_default_ignorable(ord(character)):
            raise CorpusError(
                f"{label} contains a code point a target filesystem may ignore "
                f"when comparing names ({ord(character):#06x}): {_quoted(value)}"
            )
    for character in value:
        if character == TURKIC_DOTLESS_I:
            raise CorpusError(
                f"{label} contains the Turkic dotless i "
                f"({ord(character):#06x}), which an upcase table built from "
                "Unicode's simple uppercase mappings folds onto I while this "
                f"fold key keeps it distinct: {_quoted(value)}"
            )
    for component in value.split("/"):
        # The basename is what Win32's own matcher compares, which is not
        # simply the text before the first period; _win32_device_basename
        # composes both of its rules.
        if _win32_device_basename(component) in WIN32_RESERVED_DEVICE_NAMES:
            raise CorpusError(
                f"{label} carries a Win32 reserved device name in a "
                f"component: {_quoted(value)}"
            )
    # Last of the six, so that a device name carrying a colon keeps the more
    # specific message: _win32_device_basename truncates at the colon, so
    # "CON:stream.yml" is the console before it is a stream.
    if ":" in value:
        raise CorpusError(
            f"{label} contains a colon, which Win32 reads as a stream or "
            f"drive separator: {_quoted(value)}"
        )
    return value


def _strips_to_another_name(segment: str) -> bool:
    """Whether Win32 lookup strips this component down to a different name.

    Trailing dots and spaces are removed from a component before the lookup,
    so ``"x.yaml."`` and ``"x.yaml "`` open ``"x.yaml"``. No directory listing
    emits the stripped spelling alongside the written one, and the two are not
    fold-equal, so nothing built on fold keys can pair them.

    Asked of *declared* paths by :func:`_aliases_natively` and of *tree entry
    names* by the sweep, which is the half that was missing: the declared side
    was screened from round three while the filesystem names that decide
    closed-world membership were not (peer review, round six).
    """

    return segment != segment.rstrip(". ")


def _short_name_extension(name: str) -> str | None:
    """The extension 8.3 generation gives this name, or None if it gives none.

    Derived the way Win32 derives it, in the order Win32 applies the rules,
    because the order is what decides the answer:

    - every space is removed first. Win32 strips spaces out of a name before
      it truncates, so ``"smuggled.y mlx"`` yields ``YML`` and not ``Y M``
      (peer review, round seven: truncating the raw extension read the space
      as a character and the helper answered false for a name whose alias
      really would carry the pinned suffix);
    - leading periods are then removed, so ``".yml"`` has no extension here
      at all, exactly as it has none in the short name Win32 hands out;
    - what follows the last remaining period is the extension. If no period
      remains there is none;
    - each of its characters is mapped: an ASCII letter is uppercased, an
      ASCII digit and the punctuation in :data:`SHORT_NAME_PUNCTUATION` are
      kept, and any other ASCII character — a surviving period included —
      becomes an underscore, which is what Win32 substitutes for a character
      the 8.3 namespace cannot hold;
    - the result is truncated to three characters.

    A *non-ASCII* character among those three is not mapped at all: the name
    is refused. Mapping it to an underscore was wrong in the direction that
    matters. The 8.3 namespace is an OEM code page, not ASCII, so a
    character the volume's code page can represent survives into the short
    name and is uppercased there — with ``.éml`` pinned, ``smuggled.émlx``
    is handed an alias ending ``.ÉML`` on a code page 850 volume, and the
    underscore model answered ``._ML`` and let the file be skipped as
    non-content (peer review, round eight). Which code page a volume uses is
    not something an auditor's clone reports, and guessing wrong in either
    direction is a wrong answer about closed-world membership, so the
    verifier says it cannot derive the alias rather than deriving one it
    cannot stand behind. That refusal is why an alias-capable pinned content
    suffix must be ASCII: :class:`CorpusSpec` refuses a non-ASCII one at
    construction, so a corpus cannot be configured into a state where no
    name can be judged.

    "Among those three" is the whole of the uncertainty and the whole of the
    refusal. The truncation happens before the question is asked, because a
    character past the third cannot reach the derived extension and no code
    page decides anything about it: ``x.ymlé`` yields ``YML`` on every
    volume there is, and refusing it as underivable refused an ordinary name
    over a question nobody had put (peer review, Sol round 2).

    What is modelled is the extension and nothing else. The *stem* is not:
    it depends on collisions with names this verifier cannot see, so the
    tilde-digit part of a short name is unmodellable from here. Whether 8.3
    generation is even on for the volume is not modelled either — it is a
    per-volume setting an auditor's clone cannot report. Both of those are
    why the caller refuses on the extension alone rather than reconstructing
    a short name and looking for it.
    """

    stripped = name.replace(" ", "").lstrip(".")
    _, dot, extension = stripped.rpartition(".")
    if not dot:
        return None
    # Truncation comes first, because the uncertainty this function refuses
    # over is only about characters that reach the alias. An 8.3 extension is
    # three characters, so the fourth and later characters of the extension
    # source are dropped whatever they are: refusing ``x.ymlé`` because of a
    # code page that cannot decide anything about ``YML`` was a refusal with
    # no question behind it (peer review, Sol round 2).
    source = extension[:3]
    if any(ord(character) > 0x7F for character in source):
        raise CorpusError(
            "8.3 alias extension cannot be derived for a name whose extension "
            "carries non-ASCII characters (the volume's OEM code page decides "
            f"it): {_quoted(name)}"
        )
    return (
        "".join(
            character.upper()
            if "a" <= character <= "z" or "A" <= character <= "Z"
            else (
                character
                if "0" <= character <= "9" or character in SHORT_NAME_PUNCTUATION
                else "_"
            )
            for character in source
        )
        or None
    )


def _short_name_carries_pinned_suffix(name: str, suffixes: tuple[str, ...]) -> bool:
    """Whether 8.3 generation would give this name a pinned content suffix.

    An NTFS volume with 8.3 generation on hands a long name a second,
    addressable spelling: the stem shortened with a tilde-digit and the
    extension truncated to its first three characters, uppercased. So with
    ``.yml`` pinned, a file emitted as ``smuggled.ymlx`` is not content under
    :func:`_has_pinned_suffix` — its suffix is ``.ymlx`` — while the
    ``SMUGGL~1.YML`` that opens the same bytes is content, and sits outside
    the closed world the sweep just called closed (peer review, round six).

    The alias's extension comes from :func:`_short_name_extension`, which
    applies the 8.3 rules in Win32's own order rather than truncating the
    written name. What that models, and what it does not, is stated there.

    Only a pin an alias can carry is compared, and it is compared exactly.
    An 8.3 extension is at most three characters, so a pin whose own
    extension is longer than three cannot be the extension of any alias, and
    such a pin is ignored here entirely. Truncating the pin instead and
    comparing the first three characters was unsound the other way: with
    ``.yaml`` pinned, an ordinary ``notes.yam`` was refused as though its
    alias carried the pin, although no alias of anything can end ``.yaml``
    and the file is simply not content (peer review, round eight). What is
    left is an exact comparison between the derived alias extension and a
    pin short enough to be one.

    The pins are filtered *before* the name is touched, and the order is
    load-bearing rather than tidy. Deriving first meant a name was refused
    as underivable for a configuration that had no alias-capable pin at all:
    with only ``.yaml`` pinned, ``notes.é`` raised the OEM refusal although
    the answer this function would have given is False whatever the code
    page decides (peer review, Sol round 2). Where no pin can be carried by
    an alias, there is no question, and no name is asked one.

    Compared through :func:`_path_fold`, the key by which membership is
    decided everywhere else in this module, so ``.YML`` and ``.yml`` are one
    suffix here exactly as they are there.

    A name whose alias extension cannot be derived does not reach the
    comparison: :func:`_short_name_extension` refuses it, and that refusal
    surfaces where the sweep meets the entry.
    """

    # The pins are filtered before the name is touched, which is the order
    # the two halves have to run in. An 8.3 extension is at most three
    # characters, so a pin longer than that can be carried by no alias and
    # asks nothing of this name; deriving first meant a configuration with
    # only such pins still refused ``notes.é`` as underivable, over a
    # question no pin could have asked (peer review, Sol round 2).
    capable = [suffix for suffix in suffixes if len(suffix) <= 4]
    if not capable:
        return False
    extension = _short_name_extension(name)
    if extension is None:
        # No extension, so 8.3 generation produces a short name with none
        # either, and a pinned suffix always begins with a dot.
        return False
    alias = "." + extension
    return any(_path_fold(alias) == _path_fold(suffix) for suffix in capable)


def _is_short_name(segment: str) -> bool:
    """Whether this component is shaped like a name 8.3 generation hands out.

    The grammar is what generation produces, not everything that resembles
    it: one to six characters from the short-name repertoire, a tilde, one
    to six digits, the whole stem at most eight characters, then optionally
    a period and one to three more repertoire characters.

    Accepting a tilde-digit *anywhere* inside any run of non-period
    characters was much wider than that, and it refused ordinary names for
    no benefit: ``A~1B.TXT`` has a tilde-digit but no numeric tail, so no
    collision counter produced it; ``~1foo.txt`` has nothing before the
    tilde to have been shortened; ``a ~1.txt`` carries a space, which
    generation replaces with an underscore rather than emitting (peer
    review, Sol round 2). Each was a declared path a real corpus may hold
    and this module refused outright.

    The tail is taken from the *last* tilde, because the collision counter
    is a suffix and the shortened prefix may itself contain one:
    ``A~1FOO~1.TXT`` is what generation gives a long name beginning
    ``A~1foo``, and splitting at the first tilde would not recognise it.
    """

    stem, dot, extension = segment.partition(".")
    if dot:
        if not 1 <= len(extension) <= 3:
            return False
        if any(character not in SHORT_NAME_CHARACTERS for character in extension):
            return False
    if not 1 <= len(stem) <= SHORT_NAME_STEM_LIMIT:
        return False
    prefix, tilde, digits = stem.rpartition("~")
    if not tilde:
        return False
    if not 1 <= len(prefix) <= 6:
        return False
    if any(character not in SHORT_NAME_CHARACTERS for character in prefix):
        return False
    if not 1 <= len(digits) <= 6:
        return False
    return all("0" <= character <= "9" for character in digits)


def _aliases_natively(segment: str) -> bool:
    """Whether Win32 resolves this component under a spelling nothing emits.

    Two shapes, both of which open a file the fold model would call a
    different name. Win32 strips trailing dots and spaces from a component
    before the lookup, so ``"x.yaml."`` and ``"x.yaml "`` open ``"x.yaml"``;
    and an NTFS volume with 8.3 generation on hands out a short name such as
    ``"RULESF~1.YAM"`` that opens the long name's file. Neither spelling is
    ever emitted by a directory listing, so no fold key can catch it.

    Which components count as the second shape is :func:`_is_short_name`,
    and it is the grammar generation produces rather than everything that
    resembles it — ``A~1B.TXT``, ``~1foo.txt`` and ``a ~1.txt`` are
    ordinary names no collision counter could have produced, and refusing
    them cost a corpus paths it may legitimately hold (peer review, Sol
    round 2).

    This is the *declared* side. A path a journal names is refused outright
    if it is spelled either way. What a tree entry may be named is a separate
    question, answered by :func:`_strips_to_another_name` and
    :func:`_short_name_carries_pinned_suffix` where the sweep meets it: a
    file really named ``RULESF~1.YAM`` on a POSIX host is an ordinary file,
    not an alias of anything, so the tilde shape is not refused there.

    A third Win32 spelling is *not* here, deliberately: a reserved device
    basename such as ``NUL`` or ``COM1``. It belongs to the same family —
    a name Win32 resolves to something other than the bytes on disk — but
    it is not an alias of another entry, and the question has to be asked
    of tree entries and tombstone survivors as well as of declared paths.
    :func:`_assert_foldable` asks it once, for all of them.
    """

    if _strips_to_another_name(segment):
        return True
    return _is_short_name(segment)


def _validate_relative_path(value: Any, label: str) -> str:
    """Reject anything that could escape the root or alias another entry."""

    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    if len(value) > MAX_PATH_TEXT:
        # First, so that no refusal below quotes a flood.
        raise CorpusError(
            f"{label} is longer than {MAX_PATH_TEXT} characters ({len(value)})"
        )
    if "\\" in value:
        raise CorpusError(f"{label} must use POSIX separators: {_quoted(value)}")
    if value.startswith("/") or value.endswith("/"):
        raise CorpusError(
            f"{label} must be relative with no trailing slash: {_quoted(value)}"
        )
    segments = value.split("/")
    for segment in segments:
        if not segment:
            raise CorpusError(f"{label} has an empty path segment: {_quoted(value)}")
        if segment in (".", ".."):
            raise CorpusError(f"{label} contains a relative segment: {_quoted(value)}")
        if _aliases_natively(segment):
            # Two spellings Win32 resolves that no enumeration emits, so the
            # fold model cannot see them and a tombstone or a closed-world
            # sweep would call the file absent while it still opens (peer
            # review, round three). "rules.yaml." and "rules.yaml " are the
            # same file as "rules.yaml" — the lookup strips trailing dots and
            # spaces — and "RULESF~1.YAM" is the 8.3 short name NTFS hands
            # out for a long one. A declared path spelled either way aliases
            # a path this module cannot enumerate, so it is refused rather
            # than modelled.
            raise CorpusError(
                f"{label} has a component Windows would alias: {_quoted(value)}"
            )
    _reject_control_characters(value, label)
    if ":" in value:
        # On Windows, "C:/x" survives every relative-path check above yet
        # joins drive-absolute under pathlib, letting a row reference a file
        # outside the root. No path in this schema legitimately contains a
        # colon; refuse rather than special-case the platform.
        #
        # Asked here rather than after the screen below, which now refuses a
        # colon in every name it sees. Both say the same thing; a declared
        # path keeps the words the schema has used since round three, and
        # the screen's own message is what an enumerated name gets.
        raise CorpusError(f"{label} contains ':': {_quoted(value)}")
    _assert_foldable(value, label)
    return value


def _exact_keys(row: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(row) is not dict:
        raise CorpusError(f"{label} must be a JSON object")
    actual = set(row)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise CorpusError(
            f"{label} keys are not closed-world: missing={_quoted(missing)}, "
            f"unknown={_quoted(unknown)}"
        )
    return row


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise CorpusError(
            f"{label} is not a lowercase SHA-256 hex digest: {_quoted(text)}"
        )
    return text


def _parse_row(line: str, number: int, spec: CorpusSpec) -> dict[str, Any]:
    try:
        parsed = json.loads(line, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"journal row {number} is not valid JSON: {exc}") from exc
    if type(parsed) is not dict:
        raise CorpusError(f"journal row {number} is not a JSON object")
    kind = parsed.get("kind")
    # Check the type before set membership: an unhashable JSON value such as
    # [] or {} would make `kind not in ROW_KINDS` raise TypeError instead of
    # refusing with the documented CorpusError.
    if type(kind) is not str or kind not in ROW_KINDS:
        raise CorpusError(
            f"journal row {number} has unknown kind {_quoted(kind)}; "
            f"expected one of {', '.join(sorted(ROW_KINDS))}"
        )
    row = _exact_keys(parsed, _ROW_KEYS[kind], f"journal row {number}")
    if row["schemaVersion"] != spec.schema_version:
        raise CorpusError(
            f"journal row {number} declares schema {_quoted(row['schemaVersion'])}, "
            f"but the pinned spec is {_quoted(spec.schema_version)}"
        )
    index = row["entryIndex"]
    if type(index) is not int or index != number - 1:
        raise CorpusError(
            f"journal row {number} entryIndex must be {number - 1}, "
            f"found {_quoted(index)}"
        )
    return row


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError(f"journal row has duplicate key {_quoted(key)}")
        result[key] = value
    return result


def _validate_gate(row: dict[str, Any], number: int, spec: CorpusSpec) -> GateDeclaration:
    gate_id = _string(row["gateId"], f"journal row {number} gateId")
    if GATE_ID_RE.fullmatch(gate_id) is None:
        raise CorpusError(
            f"journal row {number} gateId is malformed: {_quoted(gate_id)}"
        )
    tier = _string(row["tier"], f"journal row {number} tier")
    if tier not in GATE_TIERS:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares unknown "
            f"reproducibility tier {_quoted(tier)}"
        )
    if tier not in spec.accepted_gate_tiers:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares tier "
            f"{_quoted(tier)}, which the pinned spec does not accept"
        )
    outcome = _string(row["outcome"], f"journal row {number} outcome")
    if outcome not in GATE_OUTCOMES:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} has unknown "
            f"outcome {_quoted(outcome)}"
        )
    evidence = row["evidence"]
    if type(evidence) is not dict or not evidence:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} evidence must be "
            "a non-empty object"
        )
    # Cardinality before content, and before the first entry is looked at:
    # the per-string bounds cap what one entry costs and capped nothing
    # about how many of them one gate may carry, so a single legal row could
    # make this loop screen an unbounded number of short pairs before any
    # budget was consulted (peer review, Sol round 2).
    if len(evidence) > MAX_EVIDENCE_ENTRIES:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares "
            f"{len(evidence)} evidence entries, over the limit of "
            f"{MAX_EVIDENCE_ENTRIES}"
        )
    for key, value in evidence.items():
        if type(key) is not str or type(value) is not str:
            raise CorpusError(
                f"journal row {number} gate {_quoted(gate_id)} evidence must map "
                "strings to strings"
            )
        key_label = f"journal row {number} gate {_quoted(gate_id)} evidence key"
        value_label = (
            f"journal row {number} gate {_quoted(gate_id)} evidence value "
            f"{_quoted(key)}"
        )
        _reject_oversized_text(key, key_label)
        _reject_oversized_text(value, value_label)
        _reject_control_characters(key, key_label)
        _reject_control_characters(value, value_label)
    # A waiver is the one outcome that admits a known failure. It has to name
    # the waiver set it was excused under by digest, or "waived" is
    # unfalsifiable — and a placeholder like "x" is no more falsifiable than a
    # missing field, so the value must be a real SHA-256.
    if outcome == WAIVED:
        if "waiverSetSha256" not in evidence:
            raise CorpusError(
                f"journal row {number} gate {_quoted(gate_id)} is waived "
                "without naming evidence.waiverSetSha256"
            )
        _sha256(
            evidence["waiverSetSha256"],
            f"journal row {number} gate {_quoted(gate_id)} evidence.waiverSetSha256",
        )
    # Same principle for a gate that did not run: state why, or the
    # declaration is decoration. A whitespace-only reason is no reason.
    if outcome == NOT_RUN and not evidence.get("reason", "").strip():
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} is declared not-run "
            "without a non-empty evidence.reason"
        )
    return GateDeclaration(
        gate_id=gate_id,
        tier=tier,
        outcome=outcome,
        evidence=dict(evidence),
        entry_index=int(row["entryIndex"]),
    )


def parse_journal(
    journal_bytes: bytes, *, spec: CorpusSpec
) -> tuple[dict[str, FileBinding], dict[str, FileBinding], tuple[GateDeclaration, ...], tuple[str, ...]]:
    """Parse and validate the journal, returning the effective current view.

    Later rows supersede earlier rows for the same path — that is how an
    append-only journal records a corrected encoding without rewriting
    history. A ``removed`` row drops the path from the present view, and it
    is a claim about the tree as well as the journal: verification refuses a
    tombstoned path that is still on disk. A file that stays in the
    repository stays bound; the only way to stop binding it is to remove it.
    """

    try:
        text = journal_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusError("corpus journal is not UTF-8") from exc
    if not text.endswith("\n"):
        raise CorpusError("corpus journal must end with exactly one LF")
    # Counted, not split, and checked before the split: ``str.count`` walks
    # the text without building the list, so the list a journal can make this
    # function allocate — and everything downstream of it — is bounded by a
    # stated input size before a single row has been decoded.
    row_count = text.count("\n")
    if row_count > MAX_JOURNAL_ROWS:
        raise CorpusError(
            f"corpus journal carries {row_count} rows, over the parser "
            f"budget of {MAX_JOURNAL_ROWS}"
        )
    lines = text.split("\n")[:-1]
    if not lines:
        raise CorpusError("corpus journal is empty; genesis must bind content")

    content: dict[str, FileBinding] = {}
    attested: dict[str, FileBinding] = {}
    gates: list[GateDeclaration] = []
    gate_ids: dict[str, int] = {}
    removed: set[str] = set()
    gate_text_charged = 0

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            raise CorpusError(f"journal row {number} is blank")
        if line.endswith("\r"):
            raise CorpusError(f"journal row {number} uses CRLF, not exact LF")
        row = _parse_row(line, number, spec)
        kind = row["kind"]

        if kind == GATE_KIND:
            # Cardinality before validation, so the declaration that would be
            # the cap plus one is refused rather than checked. Comparing the
            # total after the loop meant every gate of a 2,050-gate journal
            # was validated first (peer review, Sol round 2).
            if len(gates) >= MAX_GATE_DECLARATIONS:
                raise CorpusError(
                    f"journal row {number} declares more gates than the "
                    f"verdict budget of {MAX_GATE_DECLARATIONS} declarations"
                )
            gate = _validate_gate(row, number, spec)
            # A re-declared gate would let a later row silently downgrade an
            # earlier tier; every gate is stated once per journal.
            if gate.gate_id in gate_ids:
                raise CorpusError(
                    f"journal row {number} restates gate {_quoted(gate.gate_id)} "
                    f"from row {gate_ids[gate.gate_id]}"
                )
            gate_ids[gate.gate_id] = number
            gates.append(gate)
            # And the render cost as the row is validated, refused at the
            # first gate that carries the running total over. Summing after
            # the loop bounded the verdict and nothing else: the journal that
            # cost twice the budget was decoded and validated in full before
            # the sum was compared. The gate's own evidence is summed whole,
            # because ``json.loads`` materialised the row before this point
            # and MAX_EVIDENCE_ENTRIES bounds how many entries that is.
            gate_text_charged += (
                GATE_RENDER_STRUCTURE
                + _rendered_length(gate.gate_id)
                + _rendered_length(gate.outcome)
                + sum(
                    EVIDENCE_RENDER_STRUCTURE
                    + _rendered_length(key)
                    + _rendered_length(value)
                    for key, value in gate.evidence.items()
                )
            )
            if gate_text_charged > MAX_GATE_TEXT:
                raise CorpusError(
                    "journal gate declarations cost more than the verdict "
                    f"budget of {MAX_GATE_TEXT} characters: "
                    f"{gate_text_charged} charged at declaration "
                    f"{len(gates)} (journal row {number})"
                )
            continue

        path = _validate_relative_path(row["path"], f"journal row {number} path")
        digest = _sha256(row["sha256"], f"journal row {number} sha256")
        state = _string(row["state"], f"journal row {number} state")
        if state not in FILE_STATES:
            raise CorpusError(
                f"journal row {number} has unknown state {_quoted(state)}"
            )

        target = content if kind == CONTENT_KIND else attested
        # Kind is a function of the path, not the producer's choice: the two
        # checks below decide it from the pinned roots and suffixes, so the same
        # path can never legitimately appear under both kinds and no
        # order-dependent cross-kind bookkeeping is needed.
        if kind == CONTENT_KIND and not spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {_quoted(path)} as content, but it is not "
                "under a pinned content root with a pinned suffix"
            )
        if kind == ATTESTED_KIND and spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {_quoted(path)} as attested, but it is a "
                "content path and must be swept closed-world"
            )

        if state == PRESENT:
            target[path] = FileBinding(
                path=path, sha256=digest, entry_index=int(row["entryIndex"])
            )
            removed.discard(path)
        else:
            if path not in target:
                raise CorpusError(
                    f"journal row {number} removes {_quoted(path)}, which was "
                    "never present"
                )
            # The tombstone must name the revision it retires. Otherwise
            # present(H1) → present(H2) → removed(H1) verifies, deleting the
            # effective H2 while the journal records the removal of a digest
            # that had already been superseded. (Found by cross-family review.)
            if target[path].sha256 != digest:
                raise CorpusError(
                    f"journal row {number} removes {_quoted(path)} naming digest "
                    f"{digest}, but the effective revision is "
                    f"{target[path].sha256}"
                )
            del target[path]
            removed.add(path)

    # Sorted first, so which path the refusal names is a property of the
    # journal and not of set iteration order, and so that it is the same
    # order the verdict renders them in.
    removed_paths = tuple(sorted(removed))
    charged = 0
    for number, path in enumerate(removed_paths, start=1):
        charged += REMOVED_PATH_RENDER_STRUCTURE + _rendered_length(path)
        if charged > MAX_REMOVED_TEXT:
            raise CorpusError(
                "journal removed paths total more than the verdict budget of "
                f"{MAX_REMOVED_TEXT} characters: {charged} charged at path "
                f"{number} of {len(removed_paths)}"
            )

    return content, attested, tuple(gates), removed_paths


def _list_directory(
    directory: pathlib.Path,
    relative: str,
    *,
    generations: "_DirectoryGenerations | None" = None,
) -> list[pathlib.Path]:
    """List one directory, refusing to continue if it cannot be read.

    ``Path.rglob`` swallows ``PermissionError`` while descending, so a
    directory that is searchable but not listable (mode 0111) silently
    contributes nothing to a walk while its files stay readable by exact path.
    A closed-world sweep built on that behaviour reports "no extra files"
    when it simply could not look. Enumeration failure must be a refusal, not
    an empty result. (Found by cross-family review.)

    ``generations``, when given, is told what this directory looked like an
    instant before the listing, so a later pass can be asked whether it still
    looks that way. The recorder is passed only by the *final* membership
    sweep; see :class:`_DirectoryGenerations`.
    """

    if generations is not None:
        generations.record(directory, relative)
    try:
        return sorted(directory.iterdir(), key=lambda entry: entry.name)
    except OSError as exc:
        raise CorpusError(
            f"cannot enumerate a directory under a content root, so the file "
            f"set cannot be closed: {_quoted(relative or '.')} ({exc.strerror})"
        ) from exc


def _directory_generation(
    directory: pathlib.Path,
) -> tuple[int, int, int, int] | None:
    """Identity and both change stamps of a directory, or None if unreadable.

    ``st_mtime_ns`` moves when an entry is added, removed or renamed;
    ``st_ctime_ns`` moves for those and for a metadata change as well, and
    on POSIX nothing in userspace can set it backwards. Together with the
    device and inode — which say it is still the same directory and not a new
    one swapped in under the name — that is what "this directory has not
    changed since I read it" means here.

    Only ``st_ctime_ns`` makes that a claim rather than a courtesy: mtime is
    a value ``os.utime`` restores. Windows fills the same field with the
    creation time, which restores itself, so
    :func:`verify_corpus_binding` refuses to run there at all rather than
    compare a tuple a writer can reproduce.
    """

    try:
        info = os.lstat(directory)
    except OSError:
        return None
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


class _DirectoryGenerations:
    """What each directory the closing passes read looked like when read.

    The two re-checks answer for the sets they re-derive: membership is
    re-swept and every bound file's identity is re-stated. Neither says
    anything about a directory the *second tombstone pass* reads afterwards,
    and that pass is a walk of the tree — the last window in the run, and one
    nothing was watching. A content file inserted while it ran was never
    enumerated again, and a bound file rewritten by rename while it ran kept
    the identity the re-check had already accepted (peer review, round six).

    So every directory those closing passes list is stamped an instant before
    the listing, and every stamp is re-stated once the last of them has
    finished. A directory whose generation moved refuses the verdict: an
    insertion, a removal, a rename over an existing name — each of them moves
    the parent's mtime and ctime, whatever it does to the file itself.

    What is stamped is not only what those passes *read*. Stamping the
    directories the walks happened to enumerate left every ancestor of an
    attested file unwatched, because attested paths sit outside the content
    roots and a tombstone walk only descends toward a removed path: with
    neither, nothing had ever looked at ``.axiom``, so replacing
    ``.axiom/toolchain.toml`` by rename during the second tombstone pass
    moved that directory's stamps and no stamp existed to notice (peer
    review, round seven). So every ancestor of every bound path — from the
    tree root down to the file's own parent — is stamped as well, before the
    identity re-check re-states the files themselves.

    The first reading of a directory wins. A directory the uncached tombstone
    pass lists repeatedly is therefore held against what it looked like the
    first time anything in the closing sequence read it, not the last, so the
    window the check closes is the widest one available rather than the
    narrowest.

    A directory that could not be stat-ed is kept as ``None`` and refuses at
    the re-check. That is the module's standing rule — a failure to look is
    not an absence — and in practice the listing that follows the stamp
    refuses first, with a message that says what could not be read.

    What the re-check can and cannot see is stated on
    :meth:`assert_unchanged`, which re-reads the stamps in both directions
    for the reason given there.
    """

    def __init__(self) -> None:
        self._seen: dict[
            str, tuple[pathlib.Path, tuple[int, int, int, int] | None]
        ] = {}

    def record(self, directory: pathlib.Path, relative: str) -> None:
        """Stamp this directory, if the closing sequence has not stamped it yet."""

        if relative in self._seen:
            return
        self._seen[relative] = (directory, _directory_generation(directory))

    def record_ancestors(self, root: pathlib.Path, relative: str) -> None:
        """Stamp the tree root and every directory down to this path's parent.

        A bound file's parent is not necessarily a directory either closing
        pass enumerates — an attested path sits outside the content roots,
        and the tombstone walk descends only toward a removed path — so the
        directories that hold the verdict's own subjects are stamped by name
        rather than by being walked into.
        """

        self.record(root, "")
        directory = root
        walked: list[str] = []
        for segment in relative.split("/")[:-1]:
            directory = directory / segment
            walked.append(segment)
            self.record(directory, "/".join(walked))

    def assert_unchanged(self) -> None:
        """Refuse if any stamped directory is not what it was when it was read.

        Every stamped directory is re-stated twice: once in sorted order and
        once in reverse, refusing on the first mismatch of either pass.

        The contract that gives is weaker than "one instant", and it is
        stated rather than rounded up. A single ordered pass re-states each
        directory once, so a writer who changes a directory the pass has
        already re-read is never looked at again: with the stamps taken in
        sorted order, changing the *first* while the pass is re-reading the
        *last* went unnoticed, and the residual the module claimed was one
        instant was really the span after each directory's own last re-read
        (peer review, round eight). Reading the list back the other way
        gives every directory a re-read that is late in the sequence as well
        as one that is early, so a change landing anywhere before a
        directory's final re-read is refused.

        What that leaves is the span after each directory's last re-read.
        No amount of re-read choreography removes it — a third pass and a
        fourth only move which instant is last — and nothing weaker than
        verifying an immutable snapshot can: receipt#44 tracks that.
        """

        for relative in sorted(self._seen):
            self._assert_directory_unchanged(relative)
        for relative in sorted(self._seen, reverse=True):
            self._assert_directory_unchanged(relative)

    def _assert_directory_unchanged(self, relative: str) -> None:
        """Re-state one stamped directory, refusing if it moved."""

        directory, generation = self._seen[relative]
        if generation is None or _directory_generation(directory) != generation:
            raise CorpusError(
                "the tree changed during verification; the closed-world "
                "verdict is refused"
            )


class _TombstoneIndex:
    """Every directory the tombstone pass reads, folded and indexed once.

    One :func:`verify_corpus_binding` call may carry many removed paths, and
    they overlap: each search starts at the tree root and most of them share
    their leading components. Reading a directory per removed path made the
    pass cost R×E for R tombstones over a root of E entries, and the budget
    that was supposed to bound it counted listings *per removed path*, so it
    bounded each search and nothing at all about the pass (peer review, round
    three).

    So a directory is listed once per verification and kept as
    ``{fold key: [entries]}``, shared by every subsequent search, and the work
    budget is a single running count of entries indexed for the whole pass.

    Failure to list is a refusal, not an absence, for the reason
    :func:`_list_directory` gives; a directory that is simply not there is an
    absence, cached as one.

    A listing is consumed one entry at a time and charged as it is consumed,
    so a directory wider than the budget stops the pass part-way through
    rather than being sorted and indexed whole first; each bucket is sorted
    once, here, so a search that revisits it never sorts it again.

    That is also why the listing comes from ``os.scandir`` and not from
    ``pathlib.Path.iterdir``. ``iterdir`` materialises the whole directory
    before it yields anything — 3.11 and 3.12 through ``os.listdir``, 3.13
    and 3.14 by draining ``os.scandir`` into a list — so charging per entry
    against it bounded only what this module did with the names afterwards,
    and the widest directory an adversary could plant was still read whole
    before the budget could say no (peer review, round five). ``scandir``
    fetches entries from the operating system in batches as they are
    consumed, and it is used here as a context manager, so the refusal
    raised from inside the loop closes the iterator and the batches after the
    one in hand are never asked for. What is read is bounded by the budget
    plus the batch it stopped in; what this module then does per entry — the
    sort, the screen, the fold, the index — is bounded by the budget alone.

    The cache is keyed by the directory's exact spelling as the search walked
    it — the ``/``-joined component names, ``""`` for the root — and never by
    a :class:`pathlib.Path`. Path equality and hashing are case-insensitive on
    Windows, so ``WindowsPath("A")`` and ``WindowsPath("a")`` are one key
    there; with NTFS per-directory case sensitivity they are two directories,
    and an empty ``A/`` cached under that shared key answered for a surviving
    ``a/TARGET``, turning a tombstone this pass exists to refuse into a PASS
    (peer review, round four). A string key means the cache distinguishes
    exactly what the walk distinguishes, on every platform.

    An index caches for one pass, not for one verification. The pass runs a
    second time over a second index precisely so that nothing it concluded
    from a cached listing goes unrechecked (peer review, round five), and the
    work budget belongs to the verification rather than to the index, so the
    second one is constructed with ``charged`` set to what the first spent.

    The second index caches nothing at all — ``cache=False``. A fresh index
    that still caches within itself repeats the first pass's own staleness on
    a smaller scale: one tombstone lists a shared parent, a survivor of the
    next tombstone appears in it, and the next tombstone reads the listing
    the first one left behind. Two tombstones under one directory is enough,
    and it is the exact defect the second pass exists to close (peer review,
    round six). So every tombstone in that pass lists its own directories,
    and every entry of every one of those listings is charged against the
    same carried budget — a re-read is work, and the budget bounds work.

    ``generations``, when given, is told what each directory looked like an
    instant before it was listed. See :class:`_DirectoryGenerations`: the
    second pass is the last thing in the run that reads the tree, so it is
    the one window nothing downstream can close by re-deriving a set.
    """

    def __init__(
        self,
        root: pathlib.Path,
        *,
        charged: int = 0,
        cache: bool = True,
        generations: "_DirectoryGenerations | None" = None,
    ) -> None:
        self.root = root
        self._directories: dict[str, dict[str, list[pathlib.Path]] | None] = {}
        self._work = charged
        self._cache = cache
        self._generations = generations

    @property
    def work(self) -> int:
        """Budget units charged so far, including whatever this index started at."""

        return self._work

    def charge(self, relative: str) -> None:
        """Charge one directory entry against the pass budget.

        Called for every entry consumed from a listing and for every candidate
        a search visits. ``relative`` is the removed path whose search is being
        charged, so the refusal names the tombstone that could not be checked.
        """

        self._work += 1
        if self._work > MAX_TOMBSTONE_WORK:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} (tombstone work "
                f"budget of {MAX_TOMBSTONE_WORK} entries exceeded)"
            )

    def folded(
        self, directory: pathlib.Path, key: str, relative: str
    ) -> dict[str, list[pathlib.Path]] | None:
        """This directory's entries by fold key, or None if it is not there.

        ``key`` is the directory's exact spelling relative to the tree root,
        which is what the cache is keyed by; ``relative`` is the removed path
        whose search wanted the directory, and it names the tombstone in any
        refusal this raises.
        """

        if self._cache and key in self._directories:
            return self._directories[key]
        if self._generations is not None:
            self._generations.record(directory, key)
        names: list[str] = []
        try:
            # Scanned inside a ``with`` and charged as each name arrives, so
            # the refusal below is raised from inside the loop and the
            # iterator is closed on the way out. Both halves matter: sorting
            # the listing first meant a directory of any width was sorted,
            # screened and indexed in full before anything looked at the
            # budget (peer review, round four), and reading it through
            # ``iterdir`` meant the whole of it was fetched from the
            # operating system first whatever the budget said (peer review,
            # round five).
            with os.scandir(directory) as entries:
                for entry in entries:
                    self.charge(relative)
                    names.append(entry.name)
        except (FileNotFoundError, NotADirectoryError):
            if self._cache:
                self._directories[key] = None
            return None
        except OSError as exc:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} ({exc.strerror})"
            ) from exc
        folded: dict[str, list[pathlib.Path]] = {}
        # Sorted once, here, rather than in every search that reaches this
        # directory: the order a bucket is tried in does not depend on which
        # tombstone is asking, only which spelling comes first does.
        for name in sorted(names):
            # Screened before it is folded, for the reason _assert_foldable
            # gives: a name whose equivalence class the fold key gets wrong
            # lands in one bucket here and another on the filesystem that
            # resolves it, which decides whether a tombstone is honoured.
            _assert_foldable(name, "tree entry examined for a tombstone")
            # And the other spelling no fold key can pair, asked here rather
            # than only under a content root. Win32 strips a trailing dot or
            # space before a lookup, so a surviving "retired/gone." *is* the
            # tombstoned "retired/gone" there — while the exact lstat misses
            # it on POSIX and its fold key differs, so both questions this
            # pass asks answered "absent" and the verdict named the path
            # removed with the file still openable. No host catches it in
            # passing either: the verifier refuses to run on Windows (peer
            # review, Sol round 2). Every listing screens the same way now.
            if _strips_to_another_name(name):
                raise CorpusError(
                    "tree entry Windows would alias by stripping a trailing "
                    f"dot or space: {_quoted(name)}"
                )
            folded.setdefault(_path_fold(name), []).append(directory / name)
        if self._cache:
            self._directories[key] = folded
        return folded


def _fold_survivor(index: _TombstoneIndex, relative: str) -> str | None:
    """The spelling under which a tombstoned path still answers, if any.

    The module's portability model is that two paths whose fold keys agree
    are one file on some real filesystem; the sweep and the alias guard are
    built on it, and a tombstone checked by exact-spelling lstat was not. On
    a case-sensitive host a tombstone for ".axiom/apply-manifest.json" passed
    while ".AXIOM/APPLY-MANIFEST.JSON" remained, and that survivor answers to
    the tombstoned name on a case-insensitive consumer (peer review). So each
    component is matched by fold key against a listing of its directory,
    exact spelling first, every fold-equal branch explored. An intermediate
    symlink refuses, as it does for every bound path, which also bounds the
    walk by the tree; :class:`_TombstoneIndex` reads each directory once and
    refuses a tree wider than its work budget.

    What this search cannot see is a name the filesystem resolves but never
    emits — Win32 strips trailing dots and spaces before a lookup, and NTFS
    answers to 8.3 short names. Those are handled outside this function, from
    three sides. A *declared* path spelled that way is refused at the schema
    boundary by :func:`_aliases_natively`, so no tombstone names one. A *tree
    entry* that answers to the tombstoned spelling on the running host is
    caught by the native ``os.lstat`` of the exact path in
    :func:`verify_corpus_binding`, which runs before this search and lets the
    host that is actually running decide what its own lookup resolves. And a
    tree entry that would answer to it on a host that is *not* running is
    refused outright where :class:`_TombstoneIndex` lists it: a POSIX
    ``retired/gone.`` beside a tombstone for ``retired/gone`` is invisible
    to both of the questions above and is the file itself on Win32.

    That leaves one case modelled by neither, and it is deliberate: an entry
    whose name aliases another *on Windows only*, examined on a POSIX host.
    POSIX lstat will not resolve the alias and POSIX enumeration will not emit
    it, so a tombstone can pass on Linux for a tree that would still hold the
    file on Windows. Verifying on the filesystem you intend to use is the
    remedy; this module refuses what it can see and does not pretend to model
    a lookup it is not running.
    """

    def search(
        directory: pathlib.Path, components: list[str], spelled: list[str]
    ) -> str | None:
        folded = index.folded(directory, "/".join(spelled), relative)
        if folded is None:
            return None
        head, rest = components[0], components[1:]
        # The bucket is re-ordered rather than re-sorted: the index sorted it
        # by name when it read the directory, and only which spelling to try
        # first depends on the component being matched. Sorting here instead
        # meant every tombstone that reached this bucket paid to sort it
        # again (peer review, round four).
        bucket = folded.get(_path_fold(head), ())
        matches = [entry for entry in bucket if entry.name == head]
        matches += [entry for entry in bucket if entry.name != head]
        for entry in matches:
            # A visited candidate is a directory entry examined, so it is
            # charged like an indexed one and against the same running total.
            # Re-traversing a cached bucket was free before, so R tombstones
            # over one collision bucket of K entries examined R×K candidates
            # without the budget moving (peer review, round four).
            index.charge(relative)
            if not rest:
                return "/".join([*spelled, entry.name])
            # One lstat, inside the handler, answering both questions below.
            # It sat outside: a listed entry deleted between the listing and
            # the probe raised FileNotFoundError, and an entry in a directory
            # that is readable but not searchable raised PermissionError, and
            # neither is a CorpusError — the verifier crashed where it should
            # have refused (peer review, round three). A vanished entry is not
            # a survivor; any other error means the tombstone could not be
            # checked, which is the same "failure to look is not an absence"
            # rule _list_directory states.
            try:
                info = entry.lstat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                raise CorpusError(
                    "cannot check whether a removed path is still in the tree, so "
                    f"the tombstone is unverifiable: {relative} ({exc.strerror})"
                ) from exc
            # An intermediate symlink is refused, as it is for every bound
            # path: a journal path never traverses a link. Following it
            # also made the walk unbounded, since case-varied links back
            # into the same directory branch without end (peer review,
            # round two). A link in the final position still counts as
            # present: it answers to the name.
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0):
                raise CorpusError(
                    "removed path traverses a symlink or reparse point at "
                    f"{_quoted('/'.join([*spelled, entry.name]))}: {relative}"
                )
            found = search(entry, rest, [*spelled, entry.name])
            if found is not None:
                return found
        return None

    return search(index.root, relative.split("/"), [])


def _assert_tombstones_absent(
    root: pathlib.Path,
    removed: tuple[str, ...],
    index: _TombstoneIndex,
    *,
    appeared: bool = False,
) -> None:
    """Refuse any removed path still in the tree, under any spelling.

    Two questions per tombstone, in this order. Ask the filesystem about the
    tombstoned spelling itself, then ask the fold model whether a fold-equal
    spelling survives in a listing. :func:`_fold_survivor` decides absence
    from the names a scan emits, and Win32 lookup resolves names enumeration
    never emits: a trailing dot or space is stripped before the lookup, and
    an NTFS 8.3 short name answers for a long one. Both would be reported
    absent by a search over the listing while the file opens under the
    tombstoned name (peer review, round three). The host that is running
    knows its own aliases; ask it first.

    The index arrives as a parameter rather than being built here because
    :func:`verify_corpus_binding` runs this twice over two of them, and the
    whole point of the second is that it has cached nothing. One function
    serves both calls so the two passes cannot drift apart.

    ``appeared`` says which of them is speaking, and changes nothing but the
    first clause of a refusal. On the second pass every path here was proven
    absent earlier, so a survivor is news about the tree moving under the
    verifier rather than about the journal disagreeing with the tree.
    """

    still = (
        "removed path appeared during verification"
        if appeared
        else "removed path is still present in the tree"
    )
    for path in removed:
        try:
            os.lstat(root / path)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError as exc:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {path} ({exc.strerror})"
            ) from exc
        else:
            raise CorpusError(f"{still}: {path}")
        survivor = _fold_survivor(index, path)
        if survivor is None:
            continue
        if survivor == path:
            raise CorpusError(f"{still}: {path}")
        raise CorpusError(
            f"{still} under a spelling that aliases it on a case- or "
            f"normalization-insensitive filesystem: {path} ({_quoted(survivor)})"
        )


def _path_fold(relative: str) -> str:
    """A filesystem-insensitivity-proof key for a relative path.

    NFC folds NFD/NFC spellings of the same characters together; casefold folds
    case together. Two distinct declared paths sharing a fold key would alias on
    some real filesystem, so the fold key is what closed-world uniqueness is
    checked over.
    """

    # Stable across interpreters only for assigned characters: the Unicode
    # stability policies fix case folding and normalization once a character
    # is encoded, so _validate_relative_path refuses code points outside the
    # pinned Unicode 14.0 repertoire and this key means the same thing under
    # every supported table.
    # Normalized again after folding, deliberately: casefold itself can
    # produce decomposed text (U+00DF followed by U+0301 folds to s, s,
    # U+0301, whose composed form is s, U+015B), so a variant that differs
    # in case AND normalization at once produced an unequal key and the
    # suffix predicate let it out of the sweep (peer review).
    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFC", relative).casefold()
    )


def _has_pinned_suffix(relative: str, suffixes: tuple[str, ...]) -> bool:
    """Whether a path ends in one of the pinned content suffixes, folded.

    Both sides fold, for the reason _path_fold exists: on a case-insensitive
    filesystem "rules/x.YAML" and "rules/x.yaml" are one file, so a byte-exact
    suffix match would let a case-varied spelling be classified as not-content
    and escape the sweep. The journal classifier and the tree sweep share this
    one predicate; the bug it closes was the two of them disagreeing.
    """

    folded = _path_fold(relative)
    return any(folded.endswith(_path_fold(suffix)) for suffix in suffixes)


def _reject_aliasing_paths(relatives: list[str]) -> None:
    seen: dict[str, str] = {}
    for relative in relatives:
        key = _path_fold(relative)
        if key in seen and seen[key] != relative:
            raise CorpusError(
                "two declared paths would alias on a case- or "
                "normalization-insensitive filesystem, so the closed-world set "
                f"is ambiguous: {_quoted(seen[key])} and {_quoted(relative)}"
            )
        seen[key] = relative


def _assert_no_stripping_alias(name: str, relative: str) -> None:
    """Refuse a tree entry Win32 lookup would strip down to another name.

    One function so the refusal is byte-identical wherever the sweep meets
    such a name: under a content root, and beside a component of one. The
    two are the same hazard — on the filesystem this models, the entry
    spelled with the trailing dot or space *is* the entry without it, so
    which of the two an auditor's clone holds is not a question the tree can
    answer.

    Directories are screened as well as files: ``rules /x.yaml`` and
    ``rules/x.yaml`` are one path there, and only one of them is swept here.
    """

    if _strips_to_another_name(name):
        raise CorpusError(
            f"content root contains an entry Windows would alias: {_quoted(relative)}"
        )


def _tree_content_paths(
    root: pathlib.Path,
    spec: CorpusSpec,
    *,
    generations: "_DirectoryGenerations | None" = None,
) -> dict[str, pathlib.Path]:
    """Enumerate every regular file the spec calls content.

    Walks explicitly rather than globbing: every directory is listed with
    errors surfaced, every symlink or reparse point refuses, and every
    non-regular entry refuses. What this returns is the complete set of
    content files, or the call raises — there is no third outcome where it
    returns a partial set.

    Each entry is examined through a single ``lstat``, which is both what
    makes the three questions consistent — the entry judged a directory is the
    entry judged not a link — and what lets the link question be asked in the
    form Windows answers it, since a junction there is a reparse point and not
    a symlink.

    Every path these refusals name is quoted through :func:`_quoted`, which
    is not cosmetic. A journal path is control-screened at the schema
    boundary; a *filesystem* name is not screened by anything, and the CLI
    prints refusal text into its verdict. A file named
    ``"\\x1b[2K\\rVERDICT: PASS"`` planted under a content root would have
    redrawn the line the command was about to fail on — the same attack
    :func:`_reject_control_characters` closes from the producer's side, open
    from the tree's (peer review, round three).

    ``generations``, when given, is told what every directory this walk reads
    looked like an instant before it read it — the root-component listings
    included, since a new directory aliasing a root component appears in one
    of those and nowhere else. Only the closing sweep passes a recorder;
    :class:`_DirectoryGenerations` says what it is for.
    """

    found: dict[str, pathlib.Path] = {}
    for content_root in spec.content_roots:
        base_relative = content_root.as_posix()
        # Guard every component of the root, not just its last segment: an
        # empty or suffix-empty root behind a symlinked parent would enumerate
        # nothing and silently pass. (Cross-family review finding.)
        base = _assert_no_symlinked_component(
            root, base_relative, what="pinned content root"
        )
        _assert_no_aliasing_root_component(root, base_relative, generations=generations)
        if not base.exists():
            raise CorpusError(
                f"pinned content root is absent from the tree: {base_relative}"
            )
        if not base.is_dir():
            raise CorpusError(f"pinned content root is not a directory: {base_relative}")

        pending: list[tuple[pathlib.Path, str]] = [(base, base_relative)]
        while pending:
            directory, directory_relative = pending.pop()
            for candidate in _list_directory(
                directory, directory_relative, generations=generations
            ):
                relative = candidate.relative_to(root).as_posix()
                # Before the suffix predicate folds this name, and before
                # the 8.3 model below reads its extension. A name the fold
                # key and a real filesystem disagree about — an unassigned
                # code point, a format control, a code point HFS+ ignores, a
                # Turkic i NTFS folds onto I — would decide membership one
                # way here and another on the host that resolves the tree.
                _assert_foldable(candidate.name, f"tree entry {_quoted(relative)}")
                # And before anything decides what kind of entry it is: a
                # trailing dot or space aliases a directory as readily as a
                # file, and the name is all this question needs.
                _assert_no_stripping_alias(candidate.name, relative)
                try:
                    info = candidate.lstat()
                except OSError as exc:
                    # pathlib's predicates swallow every OSError and answer
                    # False, so an entry that vanished between the listing and
                    # the probe already arrived at the non-regular refusal
                    # below. It still does; the cause is chained rather than
                    # discarded, and the text an auditor reads is unchanged.
                    raise CorpusError(
                        f"content root contains a non-regular file: {_quoted(relative)}"
                    ) from exc
                # ANY symlink under a content root defeats the closed-world
                # claim, whatever it is named: a walk does not descend
                # symlinked directories, so a linked tree of suffix-named
                # files would be invisible here while remaining reachable
                # to any consumer that resolves links.
                #
                # is_symlink() answers that for POSIX only. A Windows junction
                # — or any other directory reparse point — is not a symlink
                # and was descended as an ordinary directory, so a content
                # root could reach outside the clone entirely while the sweep
                # reported it swept (peer review, round four). st_reparse_tag
                # is how Windows reports one, and it is the same test
                # _assert_no_symlinked_component already applies to a bound
                # path's components. One lstat answers this and both questions
                # below, so nothing here can see a different file than the
                # symlink check did.
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0):
                    raise CorpusError(
                        "content root contains a symlink or reparse point: "
                        f"{_quoted(relative)}"
                    )
                if stat.S_ISDIR(info.st_mode):
                    pending.append((candidate, relative))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    # FIFOs, sockets, devices: not bindable, yet a reader could
                    # still open them where a rule file is expected. Refuse.
                    raise CorpusError(
                        f"content root contains a non-regular file: {_quoted(relative)}"
                    )
                # The same predicate the journal classifier uses, so the sweep
                # and the classifier cannot disagree about what is content.
                if not _has_pinned_suffix(relative, spec.content_suffixes):
                    # Not content under the name the listing emitted. On a
                    # volume with 8.3 generation it may still be content
                    # under the short name that opens the same bytes, and
                    # that name no listing emits, so refuse rather than skip
                    # (peer review, round six).
                    if _short_name_carries_pinned_suffix(
                        candidate.name, spec.content_suffixes
                    ):
                        raise CorpusError(
                            "content root contains a file whose short-name alias "
                            f"would carry a pinned suffix: {_quoted(relative)}"
                        )
                    continue
                found[relative] = candidate
    return found


def _assert_no_aliasing_root_component(
    root: pathlib.Path,
    relative: str,
    *,
    generations: "_DirectoryGenerations | None" = None,
) -> None:
    """Refuse a tree entry that aliases a component of a pinned content root.

    :meth:`CorpusSpec.content_root_of` folds, so a path under "RULES/" is
    classified as content wherever it is spelled. Classification is only half
    of it: the *walk* still descends the pinned spelling, so on a
    case-sensitive host "RULES/evil.yaml" is content the walk never visits,
    and it would be reported missing from the tree rather than named for what
    it is. Worse, an auditor on a case-insensitive host holds one merged
    directory and an auditor on a case-sensitive host holds two, from the
    same bytes.

    So each component of each pinned root is checked against a listing of its
    parent: an entry whose fold key matches the component but whose spelling
    does not is refused by name. A parent that is not there is left to the
    absent and not-a-directory refusals in :func:`_tree_content_paths`, which
    say something more useful, and a symlinked parent has already been
    refused by :func:`_assert_no_symlinked_component`.
    """

    current = root
    walked: list[str] = []
    for component in relative.split("/"):
        if current.is_symlink() or not current.is_dir():
            return
        for entry in _list_directory(
            current, "/".join(walked), generations=generations
        ):
            _assert_foldable(entry.name, f"tree entry beside {_quoted(relative)}")
            # The trailing-dot/space rule reaches here too, and it is not a
            # detail of tidiness: an entry named "rules " beside the pinned
            # "rules" is that root on Windows, holding whatever a producer
            # put in it, while a POSIX verifier sweeps only the spelling the
            # spec pinned. The fold check below cannot pair them — the two
            # names are not fold-equal — so the strip has to be asked
            # separately (peer review, round six).
            _assert_no_stripping_alias(entry.name, "/".join([*walked, entry.name]))
            if entry.name != component and _path_fold(entry.name) == _path_fold(
                component
            ):
                raise CorpusError(
                    f"tree entry {_quoted(entry.name)} aliases the pinned content "
                    f"root component {_quoted(component)} on a case- or "
                    "normalization-insensitive filesystem"
                )
        current = current / component
        walked.append(component)


def _assert_spelled_by_its_directory(
    parent: pathlib.Path, component: str, relative: str
) -> None:
    """Refuse a component the filesystem resolves but its directory does not emit.

    A bound path is opened by the spelling the journal declares, and on a
    case-insensitive volume that spelling need not be the one on disk: a
    spec and a journal attesting ``readme.md`` verified against a
    ``README.md`` the auditor's clone actually holds, hashed it, and passed
    — while a case-sensitive clone of the very same corpus has no
    ``readme.md`` at all and refuses. Which host the auditor cloned onto
    decided whether the corpus verified, which is the defect
    :meth:`CorpusSpec.content_root_of` closed for classification and this
    closes for binding (peer review, Sol round 2).

    So the on-disk spelling is bound, not merely the resolution: at every
    level the exact component must appear in a listing of its parent. A
    filesystem that resolves ``readme.md`` to ``README.md`` is caught by the
    listing rather than by the resolution, because the listing emits the one
    spelling the volume actually stores.

    Asked only of a component that resolves. Where nothing answers to the
    spelling there is no resolution to disagree with, and the caller's own
    refusal — a missing bound file, an absent content root — says something
    more useful than this one could. That is also why the same corpus is
    refused on both kinds of host for different reasons: the case-sensitive
    clone never resolves ``readme.md``, so it refuses as a missing file.

    Failure to list is a refusal and not an absence, which is this module's
    standing rule (see :func:`_list_directory`): a parent that resolves the
    component but cannot be enumerated leaves the question unanswered.

    The cost is one listing per component of each bound path, and it is not
    shared between paths. A cached listing would answer a later path's
    question with an earlier look, which is the staleness the second
    tombstone pass exists to avoid; the walk is already re-run per bound
    path for the same reason.
    """

    try:
        os.lstat(parent / component)
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError as exc:
        raise CorpusError(
            "cannot check the spelling a bound path component resolves "
            f"under: {relative} ({exc.strerror})"
        ) from exc
    try:
        with os.scandir(parent) as entries:
            spelled = any(entry.name == component for entry in entries)
    except OSError as exc:
        raise CorpusError(
            "cannot enumerate the directory that would spell a bound path "
            f"component, so the path cannot be bound: {relative} "
            f"({exc.strerror})"
        ) from exc
    if not spelled:
        raise CorpusError(
            f"path component {_quoted(component)} is not spelled by its "
            f"directory: {relative}"
        )


def _assert_no_symlinked_component(
    root: pathlib.Path, relative: str, *, what: str = "bound path"
) -> pathlib.Path:
    """Walk every component, refusing if any of them is a symlink or reparse.

    Checking only the final component lets an intermediate directory symlink
    put a bound file outside the clone entirely: replace ``.axiom/`` with a
    link to an ambient directory and ``.axiom/toolchain.toml`` still looks like
    a regular file and still matches its digest, while not being part of what
    the auditor cloned. (Found by cross-family review.)

    The same hole exists one level up for a content root: an empty or
    suffix-empty root behind a symlinked *parent* would enumerate no files and
    silently pass, so this guards content roots too.

    The same walk binds each component's *spelling* to the one its directory
    emits — see :func:`_assert_spelled_by_its_directory`, which every level
    passes through after the symlink question has been answered for it. The
    symlink question comes first because it is the more urgent one and
    because it is the reason the walk exists.
    """

    current = root
    for segment in relative.split("/"):
        parent = current
        current = current / segment
        # is_symlink() catches POSIX symlinks; on Windows a junction/reparse
        # point is not a symlink but is reported by st_reparse_tag, so refuse
        # any reparse point as well.
        reparse = getattr(current.lstat(), "st_reparse_tag", 0) if current.exists() else 0
        if current.is_symlink() or reparse:
            raise CorpusError(
                f"{what} traverses a symlink or reparse point at "
                f"{_quoted(current.relative_to(root).as_posix())}: {relative}"
            )
        _assert_spelled_by_its_directory(parent, segment, relative)
    return current


class _FileIdentity(NamedTuple):
    """What the descriptor said about a file at the moment it was hashed.

    ``ctime_ns`` is here for the reason :func:`_directory_generation` gives
    about directories: ``mtime`` is a value a writer sets with ``os.utime``,
    and on POSIX the inode change time is not. Without it a bound file could
    be rewritten in place through the same inode at the same size with its
    mtime restored afterwards, and the identity re-check — device, inode,
    size, mtime — saw exactly what it had seen before (peer review, round
    seven). That the module can rely on this at all is why
    :func:`verify_corpus_binding` refuses to run off POSIX.
    """

    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _regular_file_digest(root: pathlib.Path, relative: str) -> tuple[str, _FileIdentity]:
    """Hash a bound file, closing the check/open race at the final component.

    Validating the path then opening it by name leaves a window in which a
    symlink is swapped in between the check and the read. Three layers close
    it portably (cross-family review findings, two rounds):

    - ``os.lstat`` of the final component must show a regular file before the
      open — a symlink, FIFO, or device reachable by the name refuses without
      ever being opened, on every platform.
    - The open adds ``O_NOFOLLOW`` where the platform provides it and
      ``O_NONBLOCK`` unconditionally, so a FIFO raced into place between the
      ``lstat`` and the open cannot block the verifier (a read-only
      non-blocking FIFO open returns immediately; regular-file reads ignore
      the flag).
    - ``os.fstat`` of the open descriptor must agree with the ``lstat`` on
      device and inode and show a regular file — so even without
      ``O_NOFOLLOW``, a name swapped between the two calls resolves to a
      different inode and refuses.

    Residual, bounded: an intermediate directory swapped to a symlink
    *between* the component guard and this open is not caught here. Closing
    that fully needs descent by ``dir_fd``; it is left because the
    precondition is an adversary with write access to the auditor's clone
    *during* verification, who can already defeat a local check by other
    means. The post-hash sweeps in :func:`verify_corpus_binding` (membership
    re-enumeration plus per-file identity re-check) catch a resulting set
    change or file swap after the fact. A same-inode rewrite is caught there
    too, by the ``ctime_ns`` this identity carries: restoring size and
    ``mtime_ns`` afterwards is a writer's prerogative and restoring the inode
    change time is not. What stays beneath their resolution is a rewrite
    landing after that re-check has already run, which is one reason the
    verdict speaks of the bytes as they existed when hashed.
    """

    path = _assert_no_symlinked_component(root, relative)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise CorpusError(
            f"bound file is missing or not a regular file: {relative}"
        ) from exc
    if not stat.S_ISREG(before.st_mode):
        raise CorpusError(f"bound file is not a regular file: {relative}")
    flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CorpusError(
            f"bound file is missing or not a regular file: {relative}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CorpusError(f"bound file is not a regular file: {relative}")
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise CorpusError(
                f"bound file changed identity while being opened: {relative}"
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        identity = _FileIdentity(
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    finally:
        os.close(fd)
    return digest.hexdigest(), identity


def verify_declarations(
    verification: CorpusVerification, *, spec: CorpusSpec
) -> tuple[GateDeclaration, ...]:
    """Check the journal declares every gate the consumer's spec requires.

    Separate from :func:`verify_corpus_binding` so a missing declaration is
    reported as a declaration failure rather than a binding failure — the pass
    boundary the verdict describes. Row-level tier and outcome validity is
    already enforced during parsing; this is the completeness half.
    """

    declared = {gate.gate_id for gate in verification.gates}
    missing = sorted(spec.required_gates - declared)
    if missing:
        raise CorpusError(
            "the witnessed journal does not declare a gate the pinned spec "
            f"requires: {_quoted(missing[0])}"
        )
    return verification.gates


def verify_corpus_binding(
    root: pathlib.Path,
    journal_bytes: bytes,
    *,
    spec: CorpusSpec,
) -> CorpusVerification:
    """Prove the witnessed journal describes exactly this working tree.

    ``journal_bytes`` must be the same bytes the release chain verified — pass
    them through rather than re-reading the file, so nothing can change between
    the custody proof and the binding proof.

    Refuses at entry on any platform that is not POSIX. Everything this
    module claims about a tree being written to while it is read rests on
    ``st_ctime`` meaning the inode change time, which no userspace call can
    set; on Windows every supported CPython reports the file's *creation*
    time there instead, so a writer can add, remove or rename an entry, put
    the directory's mtime back with ``os.utime``, and leave the whole
    recorded tuple identical. The same holds for the ctime term in the
    bound-file identity. Refusing is the fail-closed answer; trusting a
    stamp a writer can restore would let the module's central claim be false
    while every check reported it true (peer review, round seven).
    """

    if os.name != "posix":
        raise CorpusError(
            "corpus verification requires POSIX change-time semantics "
            "(st_ctime as the inode change time) to detect a tree changing "
            "under it; on this platform the verifier refuses rather than "
            "trusting a stamp a writer can restore"
        )

    root = root.resolve()
    content, attested, gates, removed = parse_journal(journal_bytes, spec=spec)

    # Two declared paths that a case- or normalization-insensitive filesystem
    # would treat as one make the closed-world claim ambiguous: which file did
    # the auditor actually get? Detect the collision host-independently — under
    # Unicode NFC plus case folding — and refuse. Deliberately conservative: a
    # case-sensitive filesystem can hold two genuinely distinct files whose
    # names collide only after folding, and such a corpus is refused by design,
    # because its closed-world claim would depend on which filesystem the
    # auditor cloned onto.
    _reject_aliasing_paths(list(content) + list(attested))

    tree = _tree_content_paths(root, spec)
    journal_paths = set(content)
    tree_paths = set(tree)

    unlisted = sorted(tree_paths - journal_paths)
    if unlisted:
        raise CorpusError(
            f"{len(unlisted)} content file(s) in the tree are not bound by the "
            f"witnessed journal, starting with {_quoted(unlisted[0])}"
        )
    absent = sorted(journal_paths - tree_paths)
    if absent:
        raise CorpusError(
            f"{len(absent)} content file(s) bound by the journal are missing "
            f"from the tree, starting with {_quoted(absent[0])}"
        )

    # A tombstone is a claim about the tree, not only about the journal, and
    # the verdict repeats it as removedPaths. For a content path the sweep
    # above already catches a file that outlived its removal row — it is
    # unlisted. For an attested path nothing else looks: attested paths sit
    # outside the content roots, so a retired toolchain pin or apply manifest
    # could sit on disk bound by no row, reported as removed, and be read as
    # current by every consumer. Look for both kinds, by fold key so an
    # aliasing spelling counts, and refuse what is still there. One index
    # serves the whole pass: the searches overlap, and re-reading a directory
    # per removed path was what made the pass quadratic.
    #
    # Placed here, before the hashing, rather than at the end of the pass.
    # This is the longest walk of the tree the verifier does, and it used to
    # run after the only checks that look at the tree a second time, so
    # anything that changed the tree while it ran was never rechecked: a
    # content file inserted during the tombstone walk was unlisted and
    # unnoticed, and a bound file rewritten during it kept the verdict of the
    # bytes that were there before (peer review, round four). Everything that
    # follows this point re-reads the tree, so the membership re-sweep and the
    # identity re-check cover the tombstone walk too.
    #
    # This is the first of two runs. The second, at the end of the function,
    # is what re-establishes absence; this one is what makes an ordinary
    # unhonoured tombstone refuse before the verifier spends any IO hashing a
    # tree it is going to refuse anyway.
    tombstones = _TombstoneIndex(root)
    _assert_tombstones_absent(root, removed, tombstones)

    hashed: dict[str, _FileIdentity] = {}

    for path in sorted(journal_paths):
        digest, identity = _regular_file_digest(root, path)
        if digest != content[path].sha256:
            raise CorpusError(
                f"content file {_quoted(path)} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {content[path].sha256}"
            )
        hashed[path] = identity

    missing_required = sorted(spec.required_attested_paths - set(attested))
    if missing_required:
        raise CorpusError(
            "the witnessed journal does not attest a path the pinned spec "
            f"requires: {_quoted(missing_required[0])}"
        )
    for path in sorted(attested):
        digest, identity = _regular_file_digest(root, path)
        if digest != attested[path].sha256:
            raise CorpusError(
                f"attested file {_quoted(path)} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {attested[path].sha256}"
            )
        hashed[path] = identity

    # Closed-world means the set proven equal to the journal must not have
    # changed while it was being proven. Two sweeps after hashing, because
    # they catch different things (cross-family review findings, two rounds):
    # membership re-enumeration catches a file unlisted-and-inserted or a
    # bound file deleted after the first walk; the per-file identity re-check
    # catches a hashed file replaced or rewritten in place afterwards — for
    # every bound file, content and attested alike, the path must still be a
    # regular file with the device, inode, size, mtime and ctime the hashing
    # descriptor saw. The ctime term is what makes a rewrite through the same
    # inode visible: size and mtime are both values the writer restores, and
    # on POSIX the inode change time is not (peer review, round seven).
    # Re-reading every byte would be the only stronger check, and it would
    # double the verifier's IO to move the last-look boundary rather than
    # remove it. They come after every pass that reads the tree except the
    # second tombstone pass below, deliberately: every earlier pass, the
    # first tombstone walk included, is inside the window they close.
    #
    # What the second tombstone pass then does to the tree is watched by
    # generation instead of by re-derivation. Every directory this sweep
    # reads is stamped an instant before it is read, and the stamps are
    # re-stated after that pass has finished, so an insertion or a
    # rewrite-by-rename that lands while it walks moves its parent's mtime
    # and ctime and is refused — the check no third re-sweep could give,
    # because a third re-sweep would only move the boundary again (peer
    # review, round six).
    generations = _DirectoryGenerations()
    if set(_tree_content_paths(root, spec, generations=generations)) != tree_paths:
        raise CorpusError(
            "the content tree changed during verification; the closed-world "
            "set is not stable and the verdict is refused"
        )
    # Stamped before the identities are re-stated, not after, so the stamps
    # predate everything the loop below concludes. Every ancestor of every
    # bound path is taken, because the two walks stamp only what they read
    # and neither of them reads the directory holding an attested file: with
    # ``.axiom`` unstamped, replacing ``.axiom/toolchain.toml`` by rename
    # during the second tombstone pass moved that directory's mtime and
    # ctime with nothing recorded to compare them against, and the verdict
    # returned the digest of bytes the tree no longer held (peer review,
    # round seven).
    for path in sorted(hashed):
        generations.record_ancestors(root, path)

    for path in sorted(hashed):
        try:
            after = os.lstat(_assert_no_symlinked_component(root, path))
        except OSError as exc:
            raise CorpusError(
                f"bound file {_quoted(path)} disappeared during verification; the "
                "verdict is refused"
            ) from exc
        seen = hashed[path]
        if not stat.S_ISREG(after.st_mode) or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (seen.device, seen.inode, seen.size, seen.mtime_ns, seen.ctime_ns):
            raise CorpusError(
                f"bound file {_quoted(path)} changed during verification; the "
                "verdict is refused"
            )

    # And the tombstones once more, over an index that has cached nothing.
    # Absence was the one claim in the verdict that nothing re-established:
    # the re-checks above close their window over content membership and over
    # the bound bytes, and neither looks at a removed path. The first pass
    # decided absence from listings it cached and never re-read, so a
    # survivor that appeared after its parent directory had been listed was
    # missed by every later search in that pass — two tombstones sharing a
    # parent is enough — and the verdict named the path under removedPaths
    # while the file sat on disk (peer review, round five). A fresh index
    # asks the host and the listings again, after everything else has
    # finished touching the tree.
    #
    # Charged against the same budget, carried across from the first pass, so
    # a tree cannot be walked twice for the price of the cap once.
    #
    # It caches nothing within itself either. An index that cached would
    # repeat the first pass's staleness inside the pass meant to close it:
    # one tombstone lists the shared parent, the next tombstone's survivor
    # appears in it, and the next tombstone reads the listing the first one
    # left behind (peer review, round six).
    _assert_tombstones_absent(
        root,
        removed,
        _TombstoneIndex(
            root,
            charged=tombstones.work,
            cache=False,
            generations=generations,
        ),
        appeared=True,
    )

    # Last, because it is the only check that can speak for the walk above.
    # Every directory the closing sweep and that walk read is re-stated
    # here; one whose generation moved means the tree changed under a pass
    # that had nothing downstream to re-derive its claim.
    #
    # Stated exactly, because the check cannot promise what a single ordered
    # pass was described as promising. Every stamp is re-read forwards and
    # then backwards, so a change is caught if it lands before that
    # directory's final re-read; what is left is the span after each
    # directory's last re-read, and only verifying an immutable snapshot
    # removes it (receipt#44).
    generations.assert_unchanged()

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
    )
