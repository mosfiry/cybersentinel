# UI VERIFICATION — CyberSentinel X IDE (manual, this stage)

Honest scope: NO automated test runner exists in this repo yet (no
package.json / no CI job for the web layer). The following is a MANUAL
verification procedure performed against the React canvas render. It is
a procedure + result record, NOT an automated test suite, and no
automated "tests passed" claim is made.

## Performed checks (canvas render, desktop viewport)
1. Initial load — shell mounts: top bar, activity bar, sidebar, tabs,
   editor, bottom panel, agent panel, status bar all render. OK
2. Mission selection — Missions activity section lists 6 missions in
   status groups; switching updates header/status bar/agent panel. OK
3. Explorer navigation — folders expand/collapse; nested source/auth/
   and recon/subdir/ render; empty exploits/ shows "(empty)". OK
4. Multiple tabs — scanner.py + Mission Dashboard open; clicking files
   adds tabs; special views (Evidence, Findings, Scheduler, Source
   Control) open as tabs. OK
5. Close tabs — close button per tab; last-tab close -> empty state. OK
6. Bottom panel open/close — chevron toggle; editor does not distort. OK
7. Terminal scrolling — 3 mock sessions scroll; exit codes/durations/
   execution IDs visible. OK
8. Timeline event selection — detail expands inline. OK
9. Evidence selection — hash/provenance/validation rendered. OK
10. Finding selection — VERIFIED/CLAIM/UNKNOWN badges distinct. OK
11. Authorization view — full snapshot; no state-changing control. OK
12. Scheduler — 2 schedules with status. OK
13. Source control — M/A changes, diff block, commits. OK
14. Responsive — flex/min-w-0/min-h-0 layout used; sidebar fixed width;
    agent panel hides below lg; minimap hides below lg; status bar
    scrolls horizontally instead of overflowing. Checked by layout
    construction (flex shrink discipline), NOT by real browser resize —
    see Known Limitations.
15. Arabic/RTL — RTL toggle flips document direction without clipping
    (smoke test). OK
16. Long filenames — truncation via truncate + title tooltips. OK
17. Long mission names/objectives — sidebar truncates with title. OK
18. Long event descriptions — detail panel wraps (break-words). OK
19. Empty states — empty tab area, empty exploits/, no-search-results. OK
20. Error states — NOT YET: no backend, so 401/403/5xx states are not
    rendered anywhere yet (kept in WEB_API_REQUIREMENTS contract).
    NOT VERIFIED.

## Viewport sizes
The layout uses only flexbox with min-w-0/min-h-0 discipline and
fixed-width rails (44px activity / 224-256px sidebar / 240px agent),
so no horizontal overflow is expected at 1280x720+; this was verified
by construction in the render, not with a real multi-viewport browser
run. NOT VERIFIED for real browsers at 1366x768 / 1440x900 / 1920x1080.
