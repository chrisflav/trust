import Std.Net
import Std.Async
import Std.Async.DNS

/-!
# Talking to other nodes

`FEDERATION.md` §5.4 says what a node may connect to, and it is a whitelist
rather than a blocklist: an announced URL is attacker-supplied input, and
`http://169.254.169.254/` is a valid URL.  So a URL has to be dull in a
specific way — https, no credentials, no fragment, no query — and every address
it resolves to has to be a public one.

The interesting part is what happens between the check and the request.  §5.4
records a known residual risk: the address is checked by one resolution and the
request is made by another, so a name that answers honestly for the first and
privately for the second defeats it.  Closing that needs the connection pinned
to the address that was approved, and the note says the platform HTTP client
does not expose it.

`curl --resolve host:port:address` does.  Going out through a subprocess — which
Lean has to do anyway, having no TLS — is what lets this be closed rather than
documented, so `request` below never takes a hostname: it takes what `check`
returned, and that carries the address it approved.
-/

namespace Trust

open Std.Net

namespace Net

/-- §8's limits, as far as they concern one request. -/
structure Policy where
  /-- Permit `http` and private addresses.  For local mode and tests, never for a deployment. -/
  allowPrivate : Bool := false
  /-- §8: a peer's response is untrusted input. -/
  maxResponseBytes : Nat := 2 * 1024 * 1024
  /-- §8: one slow peer must not own the request. -/
  timeoutMs : Nat := 4000
  deriving Inhabited

/--
A URL that passed §5.4, and the address it passed *with*.

The address travels with the URL so that the request cannot quietly resolve the
name a second time.  That is the whole point of this type existing rather than
functions taking a `String`.
-/
structure Pinned where
  /-- The URL as normalised: scheme, host, port, path. -/
  url : String
  host : String
  port : UInt16
  /-- The literal address the connection must go to. -/
  address : String
  scheme : String
  deriving Inhabited, Repr

/-! ## Address classes -/

/-- Whether an IPv4 address is one §5.4 refuses. -/
def blockedV4 (o : Vector UInt8 4) : Bool :=
  let a := o[0]; let b := o[1]
  -- "this network", loopback, link-local, multicast and the reserved 240/4,
  -- plus the three private ranges and carrier-grade NAT.
    a == 0 || a == 10 || a == 127 || a >= 224
      || (a == 100 && b >= 64 && b <= 127)
      || (a == 169 && b == 254)
      || (a == 172 && b >= 16 && b <= 31)
      || (a == 192 && b == 168)

/-- Whether an IPv6 address is one §5.4 refuses. -/
def blockedV6 (s : Vector UInt16 8) : Bool :=
  let unspecified := s.all (· == 0)
  let loopback := s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 &&
                    s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 1
  -- fe80::/10 link-local, fc00::/7 unique-local, ff00::/8 multicast.
  let linkLocal := (s[0] &&& 0xffc0) == 0xfe80
  let uniqueLocal := (s[0] &&& 0xfe00) == 0xfc00
  let multicast := (s[0] &&& 0xff00) == 0xff00
  -- ::ffff:a.b.c.d is an IPv4 address wearing a hat, and has to be judged as one.
  let v4Mapped := s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 &&
                    s[4] == 0 && s[5] == 0xffff
  let v4Blocked :=
      v4Mapped && blockedV4 #v[(s[6] >>> 8).toUInt8, (s[6] &&& 0xff).toUInt8,
                              (s[7] >>> 8).toUInt8, (s[7] &&& 0xff).toUInt8]
  unspecified || loopback || linkLocal || uniqueLocal || multicast || v4Blocked

/-- Whether an address is one §5.4 refuses to connect to. -/
def blockedAddress : IPAddr → Bool
  | .v4 a => blockedV4 a.octets
  | .v6 a => blockedV6 a.segments

/-! ## URLs -/

/--
A peer URL, taken apart.

Hand-written rather than handed to a general URI parser, because §5.4 is a
whitelist and the safe reading of an odd URL is to refuse it.  Anything with
credentials, a fragment, a query, or a shape this does not recognise exactly is
rejected — which is the answer a general parser would have had to be talked into.
-/
def parseUrl (url : String) : Except String (String × String × Option UInt16 × String) := do
  let url := url.trimAscii.toString
  if url.isEmpty then throw "empty URL"
  let (scheme, rest) ←
    if url.startsWith "https://" then pure ("https", url.drop 8 |>.toString)
    else if url.startsWith "http://" then pure ("http", url.drop 7 |>.toString)
    else throw "a peer URL must be http or https"
  if (rest.splitOn "@").length > 1 then throw "a peer URL must carry no credentials"
  if (rest.splitOn "#").length > 1 then throw "a peer URL must carry no fragment"
  if (rest.splitOn "?").length > 1 then throw "a peer URL must carry no query"
  let slash := rest.splitOn "/"
  let authority := slash.headD ""
  let path := if slash.length > 1 then "/" ++ String.intercalate "/" slash.tail else ""
  if authority.isEmpty then throw "a peer URL must name a host"
  -- An IPv6 literal is bracketed; anything else must hold exactly one colon at
  -- most, and that colon introduces the port.
  let (host, port) ←
    if authority.startsWith "[" then
      match (authority.drop 1 |>.toString).splitOn "]" with
      | [inner, ""] => pure (inner, none)
      | [inner, portPart] =>
        if portPart.startsWith ":" then
          match (portPart.drop 1 |>.toString).toNat? with
          | some p => if p == 0 || p > 65535 then throw "port out of range"
                      else pure (inner, some (UInt16.ofNat p))
          | none => throw "unreadable port"
        else throw "unreadable IPv6 authority"
      | _ => throw "unreadable IPv6 authority"
    else
      match authority.splitOn ":" with
      | [h] => pure (h, none)
      | [h, p] =>
        match p.toNat? with
        | some p => if p == 0 || p > 65535 then throw "port out of range"
                    else pure (h, some (UInt16.ofNat p))
        | none => throw "unreadable port"
      | _ => throw "unreadable authority"
  if host.isEmpty then throw "a peer URL must name a host"
  return (scheme, host, port, path)

/--
Normalise a URL the way a node has to before comparing two of them.

§5.2 requires an announced URL to equal what the node says its own address is,
and "equal" cannot mean string equality or a trailing slash defeats the check.
-/
def normalizeUrl (url : String) : Except String String := do
  let (scheme, host, port, path) ← parseUrl url
  let host := host.toLower
  let defaultPort : UInt16 := if scheme == "https" then 443 else 80
  let portPart := match port with
    | some p => if p == defaultPort then "" else s!":{p}"
    | none => ""
  let path := if path == "/" then "" else path
  let host := if (host.splitOn ":").length > 1 then s!"[{host}]" else host
  return s!"{scheme}://{host}{portPart}{path}"

/--
Check a URL against §5.4 and pin it to an address.

The resolution happens here, once, and the address it approved is what the
request is sent to.  Every address the name resolves to is checked, not just the
first: a name that answers with one public and one private address must not be
usable to reach the private one.
-/
def check (url : String) (policy : Policy := {}) : IO (Except String Pinned) := do
  match parseUrl url with
  | .error e => return .error e
  | .ok (scheme, host, port, path) =>
    if scheme == "http" && !policy.allowPrivate then
      return .error "a peer URL must be https"
    let port := port.getD (if scheme == "https" then 443 else 80)
    let addrs ← try
        Std.Async.Async.block (Std.Async.DNS.getAddrInfo host (toString port))
      catch e => return .error s!"{host} does not resolve: {e}"
    if addrs.isEmpty then
      return .error s!"{host} does not resolve"
    if !policy.allowPrivate then
      for a in addrs do
        if blockedAddress a then
          return .error s!"{host} resolves to {a.toString}, which is not a public address"
    let address := addrs[0]!.toString
    let host := host.toLower
    let bracketed := if (host.splitOn ":").length > 1 then s!"[{host}]" else host
    let defaultPort : UInt16 := if scheme == "https" then 443 else 80
    let portPart := if port == defaultPort then "" else s!":{port}"
    return .ok {
      url := s!"{scheme}://{bracketed}{portPart}{path}", host, port, address, scheme }

/-! ## Requests -/

/-- What came back, and nothing about what it means. -/
structure Response where
  status : Nat
  body : String
  deriving Inhabited, Repr

private def runCurl (args : Array String) (stdin : String := "") : IO (Except String Response) := do
  let child ← IO.Process.spawn {
    cmd := "curl", args, stdin := .piped, stdout := .piped, stderr := .piped }
  let (h, child) ← child.takeStdin
  h.putStr stdin
  h.flush
  let out ← IO.asTask child.stdout.readToEnd .dedicated
  let err ← child.stderr.readToEnd
  let code ← child.wait
  let body ← IO.ofExcept out.get
  if code != 0 then
    return .error s!"curl failed ({code}): {err.trimAscii}"
  -- `-w` appended the status after the body, on its own line.
  match body.splitOn "\n" |>.getLast? with
  | some last =>
  let status := last.trimAscii.toString.toNat?.getD 0
  let cut := body.length - last.length - 1
    return .ok { status, body := (body.take (max cut 0)).toString }
  | none => return .ok { status := 0, body }

/--
Fetch from a pinned peer.

`--resolve` is the reason this takes a `Pinned`: it sends the request to the
address §5.4 approved rather than to whatever the name resolves to now.
`--max-filesize` is §8's response bound, and redirects are refused outright
rather than followed, which is what §5.4 asks for — a redirect is a second URL
that never went through `check`.
-/
def get (pinned : Pinned) (path : String) (policy : Policy := {}) (accept : String := "application/json") :
    IO (Except String Response) := do
  let target := s!"{pinned.url}{path}"
  runCurl #[
    "-sS", "--fail-with-body", "--no-location",
    "--resolve", s!"{pinned.host}:{pinned.port}:{pinned.address}",
    "--max-filesize", toString policy.maxResponseBytes,
    "--max-time", toString ((policy.timeoutMs + 999) / 1000),
    "-H", s!"Accept: {accept}",
    "-w", "\n%{http_code}",
    target]

/--
Send JSON to a URL.

Not pinned: this is the CLI publishing to a server the person running it named,
which is a different question from a node deciding whom to relay to.  The body
goes in on stdin, so a note holding a quote or a newline can never be read as
another argument.
-/
def postJson (url token body : String) (policy : Policy := {}) : IO (Except String Response) := do
  let auth := if token.isEmpty then #[] else #["-H", s!"Authorization: Bearer {token}"]
  runCurl (#[
    "-sS", "--no-location", "-X", "POST", url,
    "-H", "Content-Type: application/json",
    "--max-filesize", toString policy.maxResponseBytes,
    "--max-time", toString ((policy.timeoutMs + 999) / 1000),
    "-w", "\n%{http_code}"] ++ auth ++ #["--data-binary", "@-"]) body

/-- Fetch a URL the caller chose, with no pinning.  For the CLI, never for a node. -/
def getUrl (url : String) (policy : Policy := {}) : IO (Except String Response) :=
  runCurl #[
    "-sS", "--fail-with-body", "--no-location",
    "--max-filesize", toString policy.maxResponseBytes,
    "--max-time", toString ((policy.timeoutMs + 999) / 1000),
    "-H", "Accept: application/json",
    "-w", "\n%{http_code}",
    url]

end Net

end Trust
