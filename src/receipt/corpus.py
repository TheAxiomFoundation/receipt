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
    NFC plus case folding, which over the portable repertoire below is ASCII
    case-insensitivity — so a case-varied spelling of a pinned suffix, or of a
    pinned root, cannot sit outside the closed world on a filesystem that
    treats it as the same file. A tree entry that aliases a root's own
    spelling is refused by name rather than merged, and an entry that is a
    symlink or any other reparse point is refused rather than followed — a
    junction is not a symlink on Windows, and descending one would sweep a
    directory outside the clone.

    One spelling decides membership that no listing emits, and the sweep
    screens the names it is handed for it. An NTFS volume generating 8.3
    short names gives a long name a second, addressable spelling whose
    extension may be a pinned suffix although the written one is not: with
    ``.yml`` pinned, a file emitted as ``smuggled.ymlx`` is not content
    under the name the listing emitted, while the ``SMUGGL~1.YML`` that
    opens the same bytes is content and sits outside a closed world the
    sweep just called closed (peer review, round six). The extension is
    modelled the way 8.3 generation derives it — the text after the last
    remaining period, truncated to three characters and mapped into the 8.3
    character set — because deriving it from the written name instead read
    an embedded space as a character (peer review, round seven). The stem is
    not modelled, nor is whether the volume generates short names at all;
    the extension is what decides membership.

    Only a pin an alias could carry is compared, and it is compared exactly.
    An 8.3 extension is at most three characters, so a pin whose own
    extension is longer is carried by no alias; comparing the first three
    characters of a longer pin refused an ordinary ``notes.yam`` under a
    ``.yaml`` configuration although no alias can end ``.yaml`` (peer
    review, round eight). What the model no longer has to answer is which
    *characters* survive into an alias, because every name it is asked about
    is ASCII: the 8.3 namespace is an OEM code page rather than ASCII, and
    two rounds of review were spent bounding a derivation over characters
    the volume decides about. The portable-name policy below removes the
    question instead.

``attested``
    An exact path bound by digest without a sweep — the toolchain pin, the
    pinned validation workflow, an apply manifest. The consumer's spec names
    which paths it *requires*, so a producer cannot quietly drop one. The
    spelling is bound as well as the bytes: every component of every bound
    path must appear in a listing of its parent under exactly the declared
    spelling, and no *other* spelling of it may appear beside it, so a
    case-insensitive volume resolving an attested ``readme.md`` to the
    ``README.md`` it stores is refused rather than hashed, and a
    case-sensitive tree holding both is refused rather than verified for a
    consumer who can hold only one. Without the first, the same corpus
    verified on the auditor who cloned onto APFS and refused as a missing
    file on the auditor who cloned onto ext4 (peer review, Sol round 2);
    without the second, the listing was consumed only as far as the exact
    spelling and the coexisting one was never seen (peer review, Sol round
    3). Asked of attested paths, because nothing else enumerates them: a
    content path is already known to be spelled the way a listing emits it,
    since the sweep builds its set out of listing names and the membership
    comparison proves the two sets equal.
    Retiring one is recorded by a ``removed`` row, and the file has to leave
    the tree with it: a removed path still on disk refuses, whichever kind
    it was. Two questions are asked about a tombstone, in this order — does
    the host resolve the exact spelling, and does any fold-equal spelling
    survive in a listing — because a filesystem resolves names its own
    enumeration does not emit. A third class of spelling used to answer to
    neither, and the portable-name policy below removes it rather than
    modelling it: a surviving ``retired/gone.`` is the tombstoned
    ``retired/gone`` on Win32, which strips a trailing dot before the
    lookup, while the exact ``lstat`` misses it on POSIX and its fold key
    differs from the tombstone's — and it is refused as a non-portable name
    wherever a listing emits it. The pair is asked twice per verification,
    for the reason the paragraph on pass order below gives, and the second
    asking shares no listing between one tombstone and the next, so a
    directory read for an earlier tombstone cannot answer for a later one.
    The second question walks the tree, so it is bounded: every entry taken
    from a listing and every candidate a search visits is charged against
    one budget for both askings together, and a listing wider than what is
    left of that budget is abandoned part-way — unread past the batch in
    hand — rather than fetched, sorted and indexed whole.

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
mapping's length before any entry of it is validated.

Decoding is bounded a level above all three, and in three steps rather than
one. ``MAX_JOURNAL_BYTES`` is checked on the raw bytes before the decode,
because the decode is the allocation every later bound is measured against;
``MAX_JOURNAL_ROWS`` is checked by counting line feeds before the split; and
``MAX_JOURNAL_ROW_BYTES`` is checked on each row's own bytes before
``json.loads`` is asked to build an object graph out of it. Counting rows
bounded how many there were and nothing about how large one of them was, so
a single row of arbitrary size was decoded, split out and parsed with no
budget consulted (peer review, Sol round 3). Each constant is derived from
the one below it and the arithmetic is written out beside it, so what a
journal can make this module allocate is a stated function of its stated
size.

One residual is outside this module and is stated rather than fixed:
``receipt.release_chain.jsonl_line_offsets`` splits the whole journal before
this function is reached, so the release-chain half of a verification meets
an oversized journal first and with none of these bounds. That module is
pinned byte for byte by a differential harness against the source verifier
it was extracted from, so it cannot be changed here; bounding it is its own
change, against its own harness.

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
therefore stamped as well.

*When* those stamps are taken is load-bearing for the attested half. Taking
them after the hashing left one window that nothing watched at all: the
spelling walk and the hash are two separate lookups of the same name, and on
the volume the spelling check is about, a case-only rename landing between
them resolves through the declared spelling — the walk had passed, the hash
took the renamed entry's bytes, and the stamps recorded the tree as the rename
had left it (peer review, Sol round 3). So the ancestors of every attested
path are stamped before the first spelling walk reads anything, and the walk
itself is re-run for attested paths in the closing identity loop. Content
ancestors are stamped where they were, after the closing membership sweep,
because a content path's spelling is what that sweep re-derives.

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

Every name in a corpus is a *portable name*, and that policy stands in place
of the filesystem modelling this module used to carry. Each component of a
declared path, of a pinned content root, of a required attested path, of a
tree entry the closed-world sweep meets, and of an entry a tombstone search
reads must be spelled with ASCII letters, digits, ``.``, ``_`` and ``-``; it
must not end in a period; and it must not present a Win32 reserved device
basename. One screen asks all three — :func:`_assert_portable_name` — and it
refuses with one message.

The policy is what nine rounds of review argued this module into. Each round
found another way a name a POSIX verifier accepts is resolved differently
somewhere else: an OEM code page decides which characters survive into an 8.3
alias; an NTFS upcase table built from Unicode's simple uppercase mappings
folds the dotless ı onto ``I``; HFS+ ignores default-ignorable code points
when it compares names; Win32 reads a colon as a stream separator and a
backslash as a path separator, and strips a trailing dot or space before a
lookup; and a tilde-digit grammar says which names could have been generated
as aliases. Modelling each of them was wrong twice for every time it was
right — the model refused ordinary names a corpus may legitimately hold, or
missed the spelling it was built for, and the correction introduced the next
defect. A closed world cannot be closed over a name whose equivalence class
the verifier is guessing at.

What makes the guessing unnecessary is that no corpus needs those names.
Every consumer this package verifies was enumerated before the policy was
adopted — the six ``rulespec-*`` repositories and the four trees pinned under
``receipt/.extraction`` — and not one carries a filename outside the ASCII
letters, digits, ``.``, ``_`` and ``-``. So the module refuses the rest by
name. Inside that repertoire :func:`_path_fold` is ASCII case-insensitivity
and nothing else, which is a fact about the repertoire rather than a model of
a filesystem: every insensitivity a real volume adds — case on APFS and NTFS,
normalization and default-ignorables on HFS+ — either collapses onto it or
cannot arise at all, because the characters it would act on are not in the
repertoire.

A pinned content suffix is bound one step tighter, by :class:`CorpusSpec` at
construction: a period followed by one to sixteen ASCII letters or digits. A
suffix carrying a separator, or a second period, would make "ends in this
suffix" a different question from "has this extension", and the 8.3
comparison below needs the second one.

Two Win32 facts survive the policy rather than being subsumed by it, and both
are screens rather than models. ``CON``, ``PRN``, ``AUX``, ``NUL`` and the
``COM``/``LPT`` series are portable spellings that Win32 resolves to a
character device instead of to a file, so an ordinary open of
``rules/NUL.yaml`` reads the null device rather than the bytes a journal
bound and a digest witnessed. The table is pinned in this module with every
entry attributed to the source it rests on — Microsoft's naming page for all
but two, ``ntdll``'s own matcher for ``CONIN$`` and ``CONOUT$`` — and what is
matched against it is what that matcher compares, which
:func:`_win32_device_basename` derives. And 8.3 *generation* still hands a
long name a second addressable spelling, so with ``.yml`` pinned a file
emitted as ``smuggled.ymlx`` still aliases ``.YML`` and is still refused. What
the policy removes there is the other half of that question: no name in a
corpus can be *spelled* like an alias, because ``~`` is outside the
repertoire, so the tilde grammar that decided which declared paths looked
generated is gone with the modelling it needed.

The cost is real and is stated rather than hidden. A stray editor backup
``notes.yaml~`` under a content root refuses the verification, and so does a
name carrying a space, a rule file named in any script but Latin, and — since
every entry beside a component of a pinned content root is screened too — any
such name in the repository root. That is the trade the policy makes: every
name a corpus carries means the same thing on every filesystem, and where it
would not the verifier says so rather than modelling what it cannot see.
Widening the repertoire is a change to one screen; modelling a filesystem was
a change to five.

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

from receipt._unicode_repertoire import FORMAT_CONTROL_RANGES

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GATE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
#: The punctuation an 8.3 short name may carry unchanged. An ASCII character
#: outside this set, the ASCII letters and the ASCII digits is replaced by an
#: underscore when Win32 derives a short name — except a space, which is
#: removed rather than replaced, and which is why
#: :func:`_short_name_extension` strips spaces before it maps anything.
SHORT_NAME_PUNCTUATION = frozenset("$%'-_@~`!(){}^#&")
#: Every name this module screens, as one path component. The whole of the
#: portability model is here: ASCII letters, digits, ``.``, ``_`` and ``-``.
#: :func:`_assert_portable_name` asks two more questions of a component that
#: matches — that it does not end in a period, and that it does not present a
#: Win32 device basename — and the module docstring says why the three
#: together replaced five filesystem models.
#:
#: The pattern admits a leading period, because ``.axiom`` is the directory
#: every consumer corpus keeps its attested toolchain pin in and a rule that
#: refused it would refuse every corpus this package exists to verify. It
#: does not admit an empty component, nor ``.`` or ``..``, both of which end
#: in a period.
PORTABLE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+\Z")
#: A pinned content suffix: a period and one to sixteen ASCII letters or
#: digits, refused by :class:`CorpusSpec` at construction if it is anything
#: else. Tighter than a portable name by exactly what the two questions asked
#: of a suffix need. ``_has_pinned_suffix`` asks whether a path *ends in* the
#: pin, and :func:`_short_name_carries_pinned_suffix` asks whether an alias's
#: three-character extension *is* the pin; a suffix carrying a separator or a
#: second period makes those two different questions, and a suffix carrying a
#: character outside the repertoire cannot be compared against a name that is
#: inside it. Sixteen is generous for a real one, which is three or four.
CONTENT_SUFFIX_RE = re.compile(r"\.[A-Za-z0-9]{1,16}\Z")

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
#: ``len(mapping)`` before the first entry is looked at.
#:
#: What that bounds is the *validation* a gate can ask for, not its
#: decoding: ``json.loads`` has already built the mapping by the time this
#: runs, and what bounds that is the row's own bytes, which are the input.
#: The two live at different levels and both are stated rather than
#: conflated.
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
#: margin of 2,048 between them, which is 4,096.
#:
#: That margin bounds the whole *journal*, not the tree it describes, and
#: the journal is append-only: a corpus of five hundred rule files that has
#: cut four releases has written more than two thousand content rows,
#: whatever its tree holds today. So what a consumer has to watch is bound
#: paths times revisions plus tombstones, and a corpus that outgrows it
#: raises this constant. The number is stated here rather than left
#: implicit precisely so that raising it is a visible change to a
#: consumer-facing bound rather than a silent one.
MAX_JOURNAL_ROWS = 4096
#: The most bytes one journal row may occupy, checked on the row's own bytes
#: before ``json.loads`` is asked to build anything out of it.
#:
#: ``MAX_JOURNAL_ROWS`` bounds how many rows a journal may carry and says
#: nothing about how large one of them is, so a single row of arbitrary size
#: was decoded, split out, and handed to ``json.loads`` — which materialises
#: the whole object graph — before any budget had been consulted (peer
#: review, Sol round 3).
#:
#: Derived from the largest row this schema admits, which is a gate
#: declaration. Its evidence may carry ``MAX_EVIDENCE_ENTRIES`` = 64 entries
#: whose key and value are each up to ``MAX_EVIDENCE_TEXT`` = 1024
#: characters, and JSON may spell one character in as many as twelve bytes —
#: a character outside the BMP escaped as a surrogate pair, ``\uXXXX\uXXXX``
#: — so one string costs at most 12 × 1024 + 2 quotes = 12,290 bytes and one
#: entry at most 2 × 12,290 + 4 for its colon, space and comma = 24,584.
#: Sixty-four of those come to 1,573,376.
#:
#: Two megabytes is that rounded up to the next power of two, which leaves
#: 523,776 bytes for everything else in the row: the braces and separators,
#: ``entryIndex``, ``kind``, ``tier``, ``outcome``, a gate id of at most 128
#: characters, and the consumer's own pinned ``schemaVersion``, which is the
#: one term here that is not bounded by this module. A consumer whose schema
#: version is half a megabyte long has to raise this, and would know it.
MAX_JOURNAL_ROW_BYTES = 2097152
#: The most bytes one journal may occupy in total, checked before it is
#: decoded. ``MAX_JOURNAL_ROWS`` is counted after the decode, which is the
#: allocation that bounds every later one: a journal of arbitrary size became
#: a ``str`` of arbitrary size before anything looked at it.
#:
#: Derived rather than picked, and generous by construction: it is
#: ``MAX_JOURNAL_ROWS`` × ``MAX_JOURNAL_ROW_BYTES``, the product of two worst
#: cases no journal reaches at once — 4,096 rows each of them a maximal gate
#: declaration is refused by ``MAX_GATE_TEXT`` at about the second row. What
#: this bound is for is the case with no other answer: an input that is not a
#: journal at all, whose size is the only thing about it that is knowable
#: before it is decoded. The bytes are already in the caller's hand by then —
#: :func:`verify_corpus_binding` is passed the same bytes the release chain
#: verified — so what this bounds is the decode and everything downstream of
#: it, not the read.
MAX_JOURNAL_BYTES = MAX_JOURNAL_ROWS * MAX_JOURNAL_ROW_BYTES
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
            # The spec's own name input is screened here, before the path
            # rules, so a refusal names the committed spec that carries the
            # fault rather than a path. A root also reaches
            # _validate_relative_path below, which screens it again.
            for component in root.as_posix().split("/"):
                _assert_portable_name(component, "CorpusSpec content root")
            _validate_relative_path(root.as_posix(), "content root")
        if type(self.content_suffixes) is not tuple or not self.content_suffixes:
            raise CorpusError("CorpusSpec must declare at least one content suffix")
        for suffix in self.content_suffixes:
            # One rule, CONTENT_SUFFIX_RE, in place of four screens that grew
            # one review round at a time: a leading dot, a foldability screen,
            # an ASCII rule asked only of alias-capable pins, and a
            # fold-key length test to decide which those were. What a pin has
            # to be is a period and one to sixteen ASCII letters or digits;
            # the constant says why each half of that is needed, and the
            # module docstring says why the repertoire is ASCII at all.
            if type(suffix) is not str or CONTENT_SUFFIX_RE.fullmatch(suffix) is None:
                raise CorpusError(
                    "CorpusSpec content suffix must be '.' followed by one to "
                    f"sixteen ASCII letters or digits: {_quoted(suffix)}"
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

    Asked of gate evidence — the keys and the values — and of nothing else.
    It used to screen declared paths as well, and does not now: a path is a
    name, so :func:`_assert_portable_name` decides what it may carry, and
    every class refused here is outside the portable repertoire. Evidence is
    not a name and cannot be constrained that way; it is prose a producer
    writes for a reader.

    Every string this sees is written by a producer and later rendered to
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
      ``\\ud800`` inside otherwise valid UTF-8, so it survives the decode, and
      no legitimate reason carries one. The other half of why it was refused
      belonged to paths — ``os.lstat`` raises ``UnicodeEncodeError`` on one,
      a ``ValueError`` no ``OSError`` handler sees — and that half is the
      portable-name screen's now.

    Taking the Cf class whole has a cost, accepted deliberately: U+200C and
    U+200D are required spelling in Persian, Hindi and Sinhala, and U+061C
    appears in ordinary Arabic text, so a not-run reason written in them
    refuses here. The verdict quotes
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
#:     both equivalent to NUL. [The page continues with a cross-reference
#:     to its Namespaces section, trimmed here.]
#:
#: That sentence is the source of every entry below except the two named
#: next, and of the superscripts in particular, which the same page's note
#: says Windows "treats [...] as valid parts of COM# and LPT# device names,
#: making them reserved in every directory".
#:
#: CONIN$ and CONOUT$ rest on ``ntdll``'s own matcher instead:
#: ``RtlIsDosDeviceName_U`` resolves both, and Microsoft's page does not
#: list them. Two Wine files were read for that, both fetched 2026-09-03:
#: the implementation, ``dlls/ntdll/path.c``, and the conformance table in
#: ``dlls/ntdll/tests/path.c``, which is run against real Windows and
#: records ``{ "CONIN$", 0, 12, TRUE }`` — a device name, and the ``TRUE``
#: is the comment's note that it fails on Windows 7.
#:
#: COM0 and LPT0 were in this table and are not any more, because neither
#: source supports them. The sentence above lists COM1 through COM9; the
#: matcher's digit test is ``if (*end <= '0' || *end > '9') break;``, so a
#: zero is not a device there either; and the conformance table asserts it
#: directly, with ``{ "c:\\lpt0.txt", 0, 0 }`` among its cases. The entry
#: was kept as the fail-closed side of a disagreement that does not exist,
#: and its cost is real: a corpus holding an ordinary ``COM0.yaml`` was
#: refused outright (peer review, Sol round 2).
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

    Taking the text before the first period and nothing else was not enough:
    ``NUL .yaml`` ends in ``l``, so nothing about a trailing space fired, and
    one space was enough to walk a bound path past the device screen (peer
    review, round eight). The composition here is ``ntdll``'s
    ``RtlIsDosDeviceName_U``, which truncates at ``.`` or ``:`` and then
    removes trailing spaces before it matches.

    Leading spaces are *not* removed, because that matcher does not remove
    them: `` NUL.yaml`` is an ordinary name on Win32 and is one here.

    Both of the characters this composes over — the space and the colon — are
    outside the portable repertoire, so the only names that reach the table
    through :func:`_assert_portable_name` are the plain ones. The two rules
    stay because what they encode is the matcher's, not the repertoire's, and
    because a caller may reasonably ask this question of an unscreened name.
    """

    head = component
    for index, character in enumerate(component):
        if character in ".:":
            head = component[:index]
            break
    return _ascii_upper(head.rstrip(" "))


def _assert_portable_name(value: str, label: str) -> str:
    """Refuse a name outside the repertoire every filesystem agrees about.

    One screen, run everywhere this module takes a name: declared paths, the
    spec's own content roots, the tree entry names the closed-world sweep
    judges, the entry names beside a pinned root's components, and the entry
    names a tombstone search reads out of a listing. What it asks is not "is
    this name legal" but "does this module know what this name means on the
    filesystem a consumer will resolve the tree on".

    Three questions, one refusal, one message. The component must be spelled
    with ASCII letters, digits, ``.``, ``_`` and ``-``
    (:data:`PORTABLE_NAME_RE`); it must not end in a period, which Win32
    strips before a lookup, so that the entry carrying one is the entry
    beside it; and its Win32 device basename must not be in
    :data:`WIN32_RESERVED_DEVICE_NAMES`, because ``rules/NUL.yaml`` opens the
    null device there rather than the bytes a journal bound. The three are
    asked over the whole value before it is quoted back, so which of them a
    name fails is a property of the name and not of where in it the offending
    character sits.

    The module docstring says why this replaced the modelling that used to
    live here — a pinned Unicode repertoire, a default-ignorable table, the
    Turkic dotless i, a colon, a backslash, a trailing space, and an 8.3
    tilde grammar, each of them a guess at a filesystem this module cannot
    identify. The short version is that every corpus this package verifies
    was already inside the portable repertoire, so refusing the rest costs
    nothing that a real corpus carries and removes five models that were
    wrong more often than they were right.

    What that buys is stated as an equality rather than as a hope: inside the
    repertoire :func:`_path_fold` is ASCII case-insensitivity, and ASCII case
    is the one insensitivity every filesystem in question actually has. There
    is no second equivalence class left to model.

    ``value`` may be a whole relative path or a single component; the split
    is over ``/``, so a value that is already one component is screened as
    one, and every message quotes the value whole through :func:`_quoted`.
    """

    for component in value.split("/"):
        if (
            PORTABLE_NAME_RE.fullmatch(component) is None
            or component.endswith(".")
            or _win32_device_basename(component) in WIN32_RESERVED_DEVICE_NAMES
        ):
            raise CorpusError(
                f"{label} is not a portable name (ASCII letters, digits, "
                "'.', '_' and '-', not ending in '.', not a Win32 device "
                f"name): {_quoted(value)}"
            )
    return value


def _alias_capable_suffix(suffix: str) -> bool:
    """Whether an 8.3 alias extension could ever be this pinned suffix.

    An alias extension is one to three characters, so a carryable pin is a
    period and one to three more, which is a length of two to four. A pin
    longer than that is the extension of no alias, and comparing the first
    three characters of one refused an ordinary ``notes.yam`` under a
    ``.yaml`` configuration although no alias can end ``.yaml`` (peer review,
    round eight).

    The written length is the measurement, and under the portable-name policy
    that is not a shortcut: :data:`CONTENT_SUFFIX_RE` admits only ASCII
    letters and digits after the period, and NFC plus case folding changes
    neither the length nor the character count of ASCII. Measuring the fold
    key instead was necessary while a pin could be an NFD spelling of
    something non-ASCII, which is a state the schema no longer admits.

    The low end is a statement rather than a guard: the shortest pin the
    schema admits is two characters, so nothing reaching here is shorter.
    """

    return 2 <= len(suffix) <= 4


def _short_name_extension(name: str) -> str | None:
    """The extension 8.3 generation gives this name, or None if it gives none.

    Derived the way Win32 derives it, in the order Win32 applies the rules,
    because the order is what decides the answer:

    - every space is removed first. Win32 strips spaces out of a name before
      it truncates, so ``"smuggled.y mlx"`` yields ``YML`` and not ``Y M``
      (peer review, round seven: truncating the raw extension read the space
      as a character and the helper answered false for a name whose alias
      really would carry the pinned suffix). No name the sweep hands this
      function can carry a space any more — the portable repertoire holds
      none — so this rule is unreachable from there and is kept because it
      is Win32's rule and because the function is asked directly;
    - leading periods are then removed, so ``".yml"`` has no extension here
      at all, exactly as it has none in the short name Win32 hands out;
    - what follows the last remaining period is the extension. If no period
      remains there is none;
    - it is truncated to three characters, which is all an 8.3 extension
      holds;
    - each of those three is mapped: an ASCII letter is uppercased, an
      ASCII digit and the punctuation in :data:`SHORT_NAME_PUNCTUATION` are
      kept, and any other ASCII character — a surviving period included —
      becomes an underscore, which is what Win32 substitutes for a character
      the 8.3 namespace cannot hold.

    A *non-ASCII* character cannot reach any of that, because every name
    this is asked about has already passed :func:`_assert_portable_name`.
    That is the whole of what the portable-name policy does for this
    function, and it is a great deal: the 8.3 namespace is an OEM code page
    rather than ASCII, so which non-ASCII characters survive into an alias is
    the volume's decision and not this verifier's, and two review rounds went
    on bounding a derivation over characters no clone reports. With the names
    ASCII the derivation is exact rather than bounded, and the refusal it
    used to raise — "cannot be derived" — is gone with the question.

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
    # An 8.3 extension is three characters; the fourth and later characters
    # of the extension source are dropped whatever they are.
    source = extension[:3]
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
    such a pin is ignored here entirely; :func:`_alias_capable_suffix`
    decides that. Truncating the pin instead and
    comparing the first three characters was unsound the other way: with
    ``.yaml`` pinned, an ordinary ``notes.yam`` was refused as though its
    alias carried the pin, although no alias of anything can end ``.yaml``
    and the file is simply not content (peer review, round eight). What is
    left is an exact comparison between the derived alias extension and a
    pin short enough to be one.

    The pins are filtered before the name is touched, which costs nothing
    and keeps the two halves in the order they belong: where no pin can be
    carried by an alias there is no question, and no name is asked one.

    Compared through :func:`_path_fold`, the key by which membership is
    decided everywhere else in this module, so ``.YML`` and ``.yml`` are one
    suffix here exactly as they are there.
    """

    capable = [suffix for suffix in suffixes if _alias_capable_suffix(suffix)]
    if not capable:
        return False
    extension = _short_name_extension(name)
    if extension is None:
        # No extension, so 8.3 generation produces a short name with none
        # either, and a pinned suffix always begins with a dot.
        return False
    alias = "." + extension
    return any(_path_fold(alias) == _path_fold(suffix) for suffix in capable)


def _validate_relative_path(value: Any, label: str) -> str:
    """Reject anything that could escape the root or mean two things at once.

    Four shape rules and then the name screen. The shape rules are about the
    path — it must be a bounded non-empty string, relative, with no empty
    and no ``.``/``..`` segment — and they run first so that a path with one
    of those faults is told what is wrong with it as a path.

    :func:`_assert_portable_name` is the rest, and it is now the whole of the
    rest. It subsumes four screens this function used to carry separately: a
    backslash (not in the repertoire), a colon (not in the repertoire, which
    is what kept ``C:/x`` from joining drive-absolute under ``pathlib``), the
    control, format-control, surrogate and line-separator classes
    :func:`_reject_control_characters` refuses in producer text (none of them
    in the repertoire), and the two Win32 alias shapes — a trailing dot or
    space, and the 8.3 tilde grammar — which the repertoire and the
    trailing-period rule between them make unspellable. One screen and one
    message in place of five, and the module docstring says why.
    """

    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    if len(value) > MAX_PATH_TEXT:
        # First, so that no refusal below quotes a flood.
        raise CorpusError(
            f"{label} is longer than {MAX_PATH_TEXT} characters ({len(value)})"
        )
    if value.startswith("/") or value.endswith("/"):
        raise CorpusError(
            f"{label} must be relative with no trailing slash: {_quoted(value)}"
        )
    for segment in value.split("/"):
        if not segment:
            raise CorpusError(f"{label} has an empty path segment: {_quoted(value)}")
        if segment in (".", ".."):
            raise CorpusError(f"{label} contains a relative segment: {_quoted(value)}")
    _assert_portable_name(value, label)
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

    # Before the decode, because the decode is the allocation every later
    # bound is measured against: a journal of arbitrary size became a ``str``
    # of arbitrary size before anything looked at it (peer review, Sol
    # round 3).
    if len(journal_bytes) > MAX_JOURNAL_BYTES:
        raise CorpusError(
            f"corpus journal is {len(journal_bytes)} bytes, over the parser "
            f"budget of {MAX_JOURNAL_BYTES}"
        )
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
        # First, so that nothing else in this loop — not ``strip``, and
        # certainly not ``json.loads``, which materialises the whole object
        # graph — is asked to work on a row of unbounded size. The row is
        # re-encoded to measure it, which is one linear pass over text the
        # decode above has already paid for once, and it is what makes the
        # bound exact rather than a character count standing in for one.
        row_bytes = len(line.encode("utf-8"))
        if row_bytes > MAX_JOURNAL_ROW_BYTES:
            raise CorpusError(
                f"journal row {number} is {row_bytes} bytes, over the parser "
                f"budget of {MAX_JOURNAL_ROW_BYTES}"
            )
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
            # Screened before it is folded, for the reason
            # _assert_portable_name gives: a name outside the portable
            # repertoire lands in one bucket here and another on the
            # filesystem that resolves it, which decides whether a tombstone
            # is honoured. The trailing-period half of that screen is what
            # answers the spelling no fold key can pair — a surviving
            # "retired/gone." *is* the tombstoned "retired/gone" on Win32,
            # while the exact lstat misses it on POSIX and its fold key
            # differs, so both questions this pass asks used to answer
            # "absent" with the file still openable (peer review, Sol
            # round 2).
            _assert_portable_name(name, "tree entry examined for a tombstone")
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
    boundary by :func:`_assert_portable_name`, which admits neither a
    trailing period nor a tilde, so no tombstone names one. A *tree entry*
    that answers to the tombstoned spelling on the running host is caught by
    the native ``os.lstat`` of the exact path in
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

    Over the portable repertoire this is exactly ASCII case-insensitivity:
    NFC is the identity on ASCII, ``casefold`` lowercases the letters and
    leaves the digits, ``.``, ``_`` and ``-`` alone, and the second NFC has
    nothing to compose. It is written as the general fold rather than as
    ``str.lower`` because it is also asked of names that have *not* been
    screened — the siblings of an attested path's components, which are
    someone else's files — and because what it means is "the same name on
    some real filesystem", which is not a claim about ASCII.
    """

    # Normalized again after folding, deliberately: casefold itself can
    # produce decomposed text (U+00DF followed by U+0301 folds to s, s,
    # U+0301, whose composed form is s, U+015B), so a variant that differs
    # in case AND normalization at once produced an unequal key and the
    # suffix predicate let it out of the sweep (peer review). That pair is
    # outside the portable repertoire now; the key is still computed this
    # way because it is asked of unscreened names too.
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
    """Refuse two declared paths a real filesystem would treat as one.

    Two passes, because a path can alias another in two places and the
    second one was missed.

    The first compares whole paths, which is what "the closed-world set is
    ambiguous" is about: a journal binding both ``rules/x.yaml`` and
    ``rules/X.yaml`` says two different digests about one file on APFS, and
    an auditor cannot say which one they have.

    The second compares every *prefix* of every path — each ancestor
    directory and the path itself — at the depth it sits. Comparing whole
    paths alone missed the case where the collision is a directory:
    ``rules/A/x.yaml`` and ``rules/a/y.yaml`` are two distinct paths whose
    fold keys differ, so the first pass passes them, while an insensitive
    clone merges ``A`` and ``a`` into one directory holding both files —
    and the closed-world sweep, which descends the spellings the journal
    named, walks two directories on the auditor's host and one on the
    consumer's (peer review, Sol round 3). The path itself is included at
    its own depth as well, so a directory in one path colliding with a file
    in another is caught too.

    Under the portable-name policy the fold key over a declared path is
    ASCII case-insensitivity, so what both passes are asking is whether two
    spellings differ only in case. The folded prefix carries its own depth —
    it holds one separator per level — so the depth needs no key of its own.

    The whole-path pass runs first and completely, so a journal with both
    kinds of collision keeps the message that names the more specific one.
    """

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
    directories: dict[str, str] = {}
    for relative in relatives:
        components = relative.split("/")
        for depth in range(1, len(components) + 1):
            prefix = "/".join(components[:depth])
            key = _path_fold(prefix)
            previous = directories.get(key)
            if previous is not None and previous != prefix:
                raise CorpusError(
                    "two declared paths would alias at a directory: "
                    f"{_quoted(previous)} and {_quoted(prefix)}"
                )
            directories[key] = prefix


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
            root, base_relative, what="pinned content root", spelled=False
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
                # the 8.3 model below reads its extension, and before
                # anything decides what kind of entry it is — a name whose
                # equivalence class this module would have to guess at
                # decides membership one way here and another on the host
                # that resolves the tree, and it aliases a directory as
                # readily as a file.
                _assert_portable_name(
                    candidate.name, f"tree entry {_quoted(relative)}"
                )
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
            # Screened, and not only for the fold question below: an entry
            # named "rules." beside the pinned "rules" is that root on
            # Windows, holding whatever a producer put in it, while a POSIX
            # verifier sweeps only the spelling the spec pinned — and the two
            # names are not fold-equal, so the fold check cannot pair them
            # (peer review, round six). The trailing-period half of the
            # portable-name screen is what answers it.
            _assert_portable_name(
                entry.name, f"tree entry beside {_quoted(relative)}"
            )
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

    The whole listing is consumed, not the first matching entry, because
    the exact spelling being present does not mean it is the only one. A
    case-sensitive tree can hold ``.axiom/toolchain.toml`` and
    ``.axiom/TOOLCHAIN.TOML`` side by side; this check saw the first, said
    the component was spelled, and stopped — while a case-insensitive
    consumer collapses the two into one file and cannot say which of them
    the digest covers. So a sibling that folds onto the component without
    being it refuses, by name. Under the portable-name policy that is the
    only fold class left, and the component itself is ASCII, so what the
    fold key is asking here is whether some other spelling differs from the
    bound one only in case (S5R3-F3).

    Asked only of a component that resolves. Where nothing answers to the
    spelling there is no resolution to disagree with, and the caller's own
    refusal — a missing bound file, an absent content root — says something
    more useful than this one could. That is also why the same corpus is
    refused on both kinds of host for different reasons: the case-sensitive
    clone never resolves ``readme.md``, so it refuses as a missing file.

    Failure to list is a refusal and not an absence, which is this module's
    standing rule (see :func:`_list_directory`): a parent that resolves the
    component but cannot be enumerated leaves the question unanswered.

    The cost is one listing per component, and it is asked once per
    *attested* path only. Asking it of content paths as well answered a
    question the sweep had already answered — every content path that
    survives the membership comparison came verbatim out of an
    ``os.scandir`` listing — at a price of one listing per component per
    file, which for a wide content directory is quadratic in the files it
    holds and unbudgeted, in a module that budgets its other walks
    (adversarial review of the Sol round 2 fix). Nothing is cached between
    paths: a cached listing would answer a later question with an earlier
    look, which is the staleness the second tombstone pass exists to
    avoid.
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
    folded = _path_fold(component)
    spelled = False
    # Only the first fold-equal sibling is kept: it is what the refusal
    # names, and a directory an adversary has filled with case variants of
    # one component must not make this loop hold all of them.
    other: str | None = None
    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                if entry.name == component:
                    spelled = True
                elif other is None and _path_fold(entry.name) == folded:
                    other = entry.name
    except OSError as exc:
        raise CorpusError(
            "cannot enumerate the directory that would spell a bound path "
            f"component, so the path cannot be bound: {relative} "
            f"({exc.strerror})"
        ) from exc
    if not spelled:
        # First, so that a volume which resolved the declared spelling to the
        # one it stores keeps the refusal that says exactly that. The check
        # below is about two spellings coexisting, which is a different tree
        # and a different thing to tell an auditor.
        raise CorpusError(
            f"path component {_quoted(component)} is not spelled by its "
            f"directory: {relative}"
        )
    if other is not None:
        raise CorpusError(
            "directory holds another spelling of a bound path component: "
            f"{_quoted(other)} beside {_quoted(component)}"
        )


def _assert_no_symlinked_component(
    root: pathlib.Path, relative: str, *, what: str = "bound path", spelled: bool = True
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

    ``spelled=False`` turns that half off, and exactly one caller passes it:
    the content-root walk, whose components are checked a line later by
    :func:`_assert_no_aliasing_root_component`. That check asks the same
    question and answers it better — it names the entry that aliases the
    pinned spelling — so letting the generic refusal preempt it would trade
    a refusal an auditor can act on for one they cannot (adversarial review
    of the Sol round 2 fix).
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
        if spelled:
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


def _regular_file_digest(
    root: pathlib.Path, relative: str, *, spelled: bool = True
) -> tuple[str, _FileIdentity]:
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

    ``spelled`` says whether the component walk should also bind each
    component to the spelling its directory emits. Content paths pass
    ``False``, and not to save work alone: the closed-world sweep built the
    tree set out of ``os.scandir`` names and the membership comparison
    proved the journal's set equal to it, so every content path here was
    *already* emitted by a listing under exactly this spelling, and asking
    again would answer a question already answered — at a cost of one
    listing per component per file, which for a wide content directory is
    quadratic and unbudgeted in a module that budgets its other walks.
    Attested paths pass ``True``, because nothing enumerates them — and for
    the same reason :func:`verify_corpus_binding` asks the question a second
    time in its closing identity loop, where a content path again passes
    ``False``.
    """

    path = _assert_no_symlinked_component(root, relative, spelled=spelled)
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
    # auditor cloned onto. Compared at every component prefix and not only
    # whole, because the collision can be a directory: "rules/A/x.yaml" and
    # "rules/a/y.yaml" are two distinct paths that an insensitive clone holds
    # in one merged directory (peer review, Sol round 3).
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
        # spelled=False: the sweep above built its set from listing names and
        # the membership comparison proved the two sets equal, so each of
        # these paths is already known to be spelled the way a listing emits
        # it. See _regular_file_digest.
        digest, identity = _regular_file_digest(root, path, spelled=False)
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
    # Stamped before the first spelling walk, not after the hashing, because
    # the walk and the hash are two separate lookups of the same name and a
    # case-only rename between them resolves through the declared spelling on
    # the volume this check is about. The walk passed, the hash captured the
    # renamed entry, and the ancestor stamps taken afterwards recorded the
    # tree as the rename had left it — so nothing downstream could see it
    # (peer review, Sol round 3). ``.axiom`` is stamped before anything reads
    # it, and the walk's own listing is inside the window the stamps close.
    generations = _DirectoryGenerations()
    for path in sorted(attested):
        generations.record_ancestors(root, path)
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
            # The spelling question is re-asked for attested paths and not
            # for content ones, which is the same split the hashing made and
            # for the same two reasons. A content path's spelling was proved
            # by the membership comparison against a set the sweep built out
            # of listing names, and the closing sweep above has just proved
            # it again; asking here would cost a listing per component of
            # every content file for an answer already in hand. An attested
            # path is enumerated by nothing, so its only proof was the walk
            # that ran before it was hashed — and a case-only rename landing
            # between that walk and the hash left the walk's answer stale
            # with nothing after it to notice (peer review, Sol round 3).
            after = os.lstat(
                _assert_no_symlinked_component(
                    root, path, spelled=path in attested
                )
            )
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
