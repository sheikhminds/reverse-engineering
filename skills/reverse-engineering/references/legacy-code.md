# Reverse engineering legacy code and systems

Contents: 1. Clarify the goal - 2. Inventory - 3. Establish ground truth with characterization tests - 4. Trace behavior - 5. Extract business rules - 6. Language and platform notes - 7. Deliverables - 8. Pitfalls

Read `SKILL.md` first for scope and the core loop. Here the "black box" is a system that works but that nobody fully understands: source with no docs, the original authors gone, tests absent. Sometimes you have the source and sometimes only the running system and its data. If you have only compiled artifacts, combine this with `binaries.md`.

## 1. Clarify the goal

The goal sets the depth, so settle it first.

| Goal | What you need to produce |
|---|---|
| **Understand** it well enough to maintain it | A system map, an entry-point list, a glossary, and notes on dangerous areas |
| **Migrate or rewrite** it | A behavior inventory, a rule catalog, a data dictionary, and a characterization test suite |
| **Integrate** with it | Interfaces: inputs, outputs, schemas, protocols, timing, and failure modes |
| **Audit** it | Data flows, trust boundaries, hard-coded secrets and configuration, and unusual or risky constructs |

When in doubt, aim for the migration deliverables, because they include the others.

## 2. Inventory

Build the map from the outside in before reading any function in depth.

- **Repository shape:** directory tree, languages and line counts (`find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head`, or `cloc` if present), build system, dependency manifests, and vendored libraries (skip these when reading).
- **Entry points:** every way execution begins. `main`, web routes, message consumers, scheduled jobs (`crontab`, Windows Task Scheduler, batch job definitions), triggers, stored procedures, startup scripts, hooks and plugins.
- **Data stores:** database schemas and migrations, flat files, queues, caches, file drops, and who reads or writes each.
- **External integrations:** other services, FTP sites, email, printers, hardware, and shared folders. These are the system's real interfaces.
- **Configuration:** config files, environment variables, feature flags, and per-environment differences. Much behavior lives here.
- **History:** `git log` helps even in messy repositories. High-churn files are the active core. Commit messages and linked tickets are documentation. `git blame` on a puzzling line often explains it.

Produce the system map early (a Mermaid diagram of components, data stores, and external systems) and keep refining it.

## 3. Establish ground truth with characterization tests

You can't change or replace what you can't verify. A **characterization test** (golden master) records what the system *currently does* for a given input, correct or not, so that you can detect any difference later.

1. Choose representative inputs: typical, boundary, and weird. Real production-like data (anonymized) is best.
2. Run the system, capture the outputs (return values, files written, database rows changed, messages sent).
3. Store input/output pairs as test fixtures, and write a runner that compares them.
4. Add cases whenever you discover surprising behavior.

Treat existing behavior as the specification until the owners say otherwise. Odd-looking behavior (a rounding rule, a skipped record) may exist for a reason that nobody remembers and a customer depends on.

## 4. Trace behavior

- **Follow the data.** Pick one important output (an invoice, a report, an export file) and trace it backward to the inputs and transformations that produce it. One thread followed end to end teaches more than skimming everything.
- **Call graph.** Build it for the parts you care about, using the language's tooling or a quick script. Find the functions with the most callers (shared utilities, central state) and the most callees (orchestrators).
- **Find the hidden coupling:** shared global state, database triggers, files used as mailboxes between processes, and implicit ordering ("job B only works after job A").
- **Comments and names are claims, not facts.** They're useful hints, and they go stale. Check them against what the code does and mark disagreements.
- **Dead code and flags.** Code reachable only under a flag, a date, or a customer ID may be dead or may be vital. Use logs, git history, and the user's knowledge to tell them apart, and don't assume.
- **Run it** in a safe environment when you can: add logging or a debugger, and observe real values. Observation settles questions that reading leaves open.

## 5. Extract business rules

Business rules are the part of a legacy system worth most to the people who depend on it, and the part most likely to be lost in a rewrite.

Look for: conditionals on domain values, magic numbers and constants, lookup tables, date and calendar logic (fiscal years, holidays, cut-off times), rounding and currency handling, validation rules, and status transitions.

Record each rule in a catalog:

| ID | Rule in plain language | Source (file:line) | Inputs | Example | Confidence |
|---|---|---|---|---|---|
| R-014 | Orders over 500 units get 4% discount unless customer class is "W" | `pricing.cbl:812` | qty, class | 600 units class A -> 4% | Confirmed (test case 31) |

Where the code and the stated policy disagree, record both and flag it for a person who knows the domain. Don't decide silently which is right.

## 6. Language and platform notes

| Platform | What to know |
|---|---|
| **COBOL** | Data layout lives in **copybooks** and `PIC` clauses; `REDEFINES` overlays the same bytes with different meaning; `COMP-3` is packed decimal (two digits per byte, sign in the last nibble); `PERFORM` is a procedure call; fixed-width records mean the "schema" is the copybook. JCL describes batch job flow |
| **VB6 / Delphi / PowerBuilder / Access** | Logic hides in **form event handlers** and in the database as queries and macros, not just modules. Export the forms and look at each control's handler |
| **Stored procedures and triggers** | Dump the schema with definitions. Triggers fire implicitly, so list them per table and read them before concluding that "nothing else updates this column" |
| **Shell, Perl, awk, cron** | Behavior depends on the environment: `PATH`, locale, working directory, and tools installed. Record them |
| **Excel/VBA macros** | Business logic often sits in cell formulas and named ranges. Export formulas, inspect hidden sheets, and trace precedents |
| **Old PHP/ASP/JSP** | Logic is mixed with markup. Request parameters are the interface. Map each route to its handlers and database calls |
| **Jars/DLLs without source** | Decompile (`javap`, a Java decompiler, .NET tools) to get structure back, then treat the output as source. See `binaries.md` |
| **Mainframe/fixed-width data files** | Treat as a file format problem: see `file-formats.md`, including encodings such as EBCDIC (`cp037` in Python) |

## 7. Deliverables

Produce what the goal needs from this set, and keep them in the repository next to the code:

- **System map:** components, data stores, external systems, and the main flows (Mermaid).
- **Entry-point and job inventory.**
- **Data dictionary:** each table or file, each field, meaning, units, valid values, and who writes it.
- **Business rule catalog** (table above).
- **Glossary:** the domain's vocabulary as used in the code (abbreviations, status codes).
- **Characterization test suite** and instructions to run it.
- **Risk register:** fragile areas, single points of failure, hard-coded credentials and paths, unsupported dependencies, and undocumented manual steps.
- **Open questions** for people who know the domain, written so they can answer quickly.

## 8. Pitfalls

- **Assuming the code is the whole system.** Manual steps, spreadsheets, and tribal knowledge are part of it. Ask the user what people do by hand around the software.
- **Fixing while discovering.** Change nothing until you have characterization tests. "Obvious bugs" are sometimes load-bearing.
- **Reading everything.** Trace the paths that matter for the goal, and summarize the rest.
- **Trusting stale docs, comments, and diagrams** over the behavior you've observed.
- **Environment-specific behavior:** time zones, locale, file encodings, line endings, and operating-system quirks. When results differ between machines, suspect these first.
