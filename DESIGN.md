# trust

This repository aims to contain a tool to estimate the trust debt of a
Lean statement. Trust is evaluated on a variety of metrics and
every individual has their own requirements for trusting a statement.

For this, we need to collect data and visualise it.

## Data to be collected

For a given Lean declaration, we need:

- all definitional (i.e. data carrying) dependencies of the statement as
  a complete tree
- all forward dependencies (including theorems) in a configured set
  of Lean repositories

## Visualisation

For a given Lean declaration, show:

- direct definitional dependencies appearing in the statement
- when clicking on a dependency, descend to its dependencies
- full definition dependency graph

For any node, provide two ways to navigate further to show its forward
or backward dependencies.

More features:

- filter definitions by repository
- show properly syntax-highlighted declarations (without proof body for theorems,
  with body for definitions)
- clicking on a declaration in the definition / statement code, focusses
  on that declaration

## Characterizes tag

Add a Lean attribute `@[characterizes <lean-def>]` that records that
a given declaration (theorem etc.) characterizes `lean-def`.

Visualise these characterization relations with definitions and classification
theorems.

Add a mode to the frontend that takes characterization tags into account. In this
mode, if a `lean-def` has a characterization, cut of its dependency tree and
replace it by the characterising theorems instead.
(in this cases, the dependency tree needs to continue with the dependency tree of the
classification theorems)

## Further features

- Add an interactive way to declare declarations as trusted in a local
  database (pinned at a commit).
- Add an interactive way to declare a certain definition is characterized by
  a certain theorem (or theorems).
- Mark declarations as protected, including their
  semantic hash (in the sense of https://github.com/mathlib-initiative/semantic_hash).

  Store a semantic hash of protected declarations at snapshots (indexed by commit hashes).

  Warn when protected declarations are changed compared to the latest commit
  (Make this available on demand and in the visualisation. Also provide an
  environment linter that flags protected declarations with changed semantic hash.)

## Implementation

Use the tool https://github.com/mathlib-initiative/aftk for dependency analysis
if possible. Any further data computations need to be done in Lean.

The visualisation should be provided as a frontend, written in typescript.
