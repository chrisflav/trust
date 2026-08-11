import Std.Http
import Std.Http.Server
import Std.Async
import Std.Net
import Trust.Marks
import Trust.Hash

/-!
# Serving the marks file

`DESIGN.md` asks for an interactive way to declare a declaration trusted, and
those judgements live in a version-controlled file rather than in a generated
index.  A static site cannot write files, so the editing half only exists while
a dev server is running.

That server used to be a Vite middleware in TypeScript, and it had a hole it
could not close: recording a *hash* snapshot needs the Lean environment, so a
declaration protected from the browser read as `protected, no snapshot` until
somebody remembered to run `trust protect` for it.  This one holds the
environment, so it records the hash on the spot.

Snapshots are still merged here rather than sent by the browser.  A snapshot is
the one part of the file that cannot be recomputed, and a round trip through a
client that has no reason to know about it is exactly how such things get
dropped.
-/

namespace Trust

open Std Std.Http Std.Async Std.Net

/--
Fold the browser's edits into what is on disk.

The browser decides *which* declarations are marked and why; everything else —
the recorded history, and a hash for anything newly protected — is the server's,
because the browser has no way to know it.
-/
def mergeMarks (incoming existing : Marks) (commit : String)
    (hashOf : String → IO (Option (String × String))) : IO Marks := do
  let known := existing.protectedDecls
  let mut merged : Array ProtectedMark := #[]
  for entry in incoming.protectedDecls do
    let previous := known.find? (·.name == entry.name)
    let snapshots := (previous.map (·.snapshots)).getD #[]
    -- Newly protected, and we can hash: record it now.  This is the whole
    -- reason for a Lean server rather than a middleware.
    let snapshots ←
      if snapshots.isEmpty then
        match ← hashOf entry.name with
        | some (hash, hasher) => pure (snapshots.push { commit, hash, hasher })
        | none => pure snapshots
      else pure snapshots
    merged := merged.push { name := entry.name, note := entry.note, snapshots }
  return { incoming with protectedDecls := merged }

private def json (status : Status) (body : String) : Async (Response Body.Any) := do
  let full ← Body.Full.ofString body
  return Response.withStatus status
    |>.header! "Content-Type" "application/json"
    -- The dev server is the only thing that talks to this, and it proxies
    -- same-origin, so there is nothing to relax here.
    |>.body (Body.Any.ofBody full)

/--
The marks endpoint: `GET` to read, `PUT` to write.

Deliberately the same two verbs and the same shape the Vite middleware had, so
that the frontend did not have to change when this replaced it.
-/
def marksHandler (marksPath : System.FilePath)
    (hashOf : String → IO (Option (String × String))) : Server.StatelessHandler where
  onRequest := fun request => do
    let path := toString request.line.uri.path
    if path != "/api/marks" then
      return ← json .notFound "{\"error\":\"not found\"}"
    match request.line.method with
    | .get =>
      let marks ← Marks.load marksPath
      return ← json .ok (Lean.Json.pretty (Lean.toJson marks))
    | .put =>
      let body : String ← request.body.readAll (maximumSize := some (4 * 1024 * 1024))
      match Lean.Json.parse body >>= Lean.fromJson? (α := Marks) with
      | .error e => return ← json .badRequest s!"\{\"error\":\"unreadable marks: {e}\"}"
      | .ok incoming =>
        let existing ← Marks.load marksPath
        let commit ← currentCommit
        let merged ← mergeMarks incoming existing commit hashOf
        merged.save marksPath
        return ← json .ok (Lean.Json.pretty (Lean.toJson merged))
    | _ => return ← json .methodNotAllowed "{\"error\":\"unsupported method\"}"

/--
Serve the marks file until interrupted.

Bound to loopback, because this writes a file in the working directory on
request and has no authentication at all: it is a development tool, and the
address is the whole of its security.
-/
def serveMarks (marksPath : System.FilePath) (port : UInt16)
    (hashOf : String → IO (Option (String × String))) : IO Unit := Async.block do
  let addr := SocketAddress.v4 { addr := IPv4Addr.ofParts 127 0 0 1, port }
  let server ← Server.serve addr (marksHandler marksPath hashOf)
  IO.eprintln s!"trust: serving {marksPath} on http://127.0.0.1:{port}/api/marks"
  IO.eprintln "trust: point the frontend's dev server at it, and press Ctrl-C to stop"
  server.waitShutdown

end Trust
