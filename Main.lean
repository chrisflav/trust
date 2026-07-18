import Trust

open Lean

unsafe def main (args : List String) : IO UInt32 := do
  try
    initSearchPath (← findSysroot)
    -- Required because `importModules (loadExts := true)` initializes imported extensions.
    Lean.enableInitializersExecution
    Trust.run args
  catch e =>
    IO.eprintln s!"error: {e}"
    return (1 : UInt32)