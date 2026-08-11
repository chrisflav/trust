import Std.Time

/-!
# Timestamps

Claims and revocations date themselves in RFC 3339, UTC, to the second.  That
string is part of what a signature covers, so the format is not a display
choice: `asserted` is compared against `revoked` to decide whether a withdrawal
suppresses a certificate (`FEDERATION.md` §6.2), and a receiver must be able to
parse it at all before it will store anything (§3.4 rule 1).

This used to spawn `date -u +%Y-%m-%dT%H:%M:%SZ`.  `Std.Time` does it in
process, which removes a subprocess from the path that issues a certificate and,
more usefully, gives us parsing and comparison — neither of which `date` was
ever going to provide.
-/

namespace Trust

open Std.Time

/--
The shape every `asserted` and `revoked` field has: RFC 3339, UTC, seconds.

The trailing `Z` is written literally rather than as an offset, because that is
what the strings already in circulation say, and the string is signed as it
stands.  `+00:00` would mean the same instant and verify against nothing.
-/
def rfc3339Format : GenericFormat .any := datespec("uuuu-MM-dd'T'HH:mm:ss'Z'")

/-- The current time, as a claim dates itself. -/
def nowRFC3339 : IO String := do
  let now ← Timestamp.now
  return rfc3339Format.format (DateTime.ofTimestampWithZone now .UTC)

/--
Read a timestamp that someone else wrote.

Both spellings are accepted — `Z` and a numeric offset — because §3.4 asks only
that `asserted` be parseable, and a node that refused `+00:00` would be
rejecting entries a conforming implementation is entitled to send.
-/
def parseRFC3339? (s : String) : Option Timestamp :=
  match rfc3339Format.parse s with
  | .ok dt => some dt.toTimestamp
  | .error _ =>
    match Formats.iso8601.parse s with
    | .ok dt => some dt.toTimestamp
    | .error _ => none

/-- Whether `s` is a timestamp at all, which is §3.4 rule 1's last clause. -/
def isRFC3339 (s : String) : Bool := (parseRFC3339? s).isSome

/--
Whether `a` is not later than `b`, both being RFC 3339.

This is the comparison §6.2 is written in: a revocation suppresses the
certificates whose `asserted` is **not later than** its `revoked`, so a
certificate asserted at exactly the revocation's instant is suppressed, and one
asserted a second later reinstates.

Unparseable inputs answer `false`: a comparison that cannot be made must not
silently become a suppression.
-/
def notLaterThan (a b : String) : Bool :=
  match parseRFC3339? a, parseRFC3339? b with
  | some ta, some tb => ta.toNanosecondsSinceUnixEpoch ≤ tb.toNanosecondsSinceUnixEpoch
  | _, _ => false

/-- Strictly later, for §3.5's "the entry with the later `asserted` wins". -/
def laterThan (a b : String) : Bool :=
  match parseRFC3339? a, parseRFC3339? b with
  | some ta, some tb => tb.toNanosecondsSinceUnixEpoch < ta.toNanosecondsSinceUnixEpoch
  | _, _ => false

/-- Epoch milliseconds, which is the first half of a §4.3 cursor. -/
def nowEpochMillis : IO Int := do
  let now ← Timestamp.now
  return now.toMillisecondsSinceUnixEpoch.val

end Trust
