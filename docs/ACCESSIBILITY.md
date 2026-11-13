# Accessibility (F079, F080)

What was checked on the dashboard and its pages, what was fixed, and what has not been
tested.

## Checked and fixed

| Check | Result |
|---|---|
| Colour contrast of every text token, both themes (WCAG 2.1 AA, 4.5:1) | Fixed: light-theme muted text 3.5 → 5.3:1; white on primary buttons 4.4 → 5.3:1 (light) and 3.6 → 5.0:1 (dark); red text in dark mode 3.6 → 5.8:1 (new `--critical-ink`); MEDIUM icon 2.6 → 3.8:1 (icons need 3:1) |
| Colour is never the only cue | Risk levels always show an icon (triangle / diamond) and the word HIGH / MEDIUM; comparison cells use ≠ / = |
| Every button, link and form field has an accessible name | Script audit of the dashboard and every page; fixed the triage notes box (no label) |
| Heading order | Fixed the What-if page (h1 → h3 jump) |
| Duplicate ids, positive tabindex, images without alt | none found |
| Keyboard | All actions are buttons or links; `j`/`k`, `/`, `?`, Ctrl+K (⌘K) palette with arrow keys; dialogs close with Esc; the tour moves focus to its Next button and returns it afterwards |
| Focus visible | `:focus-visible` outline everywhere; 3 px in high-contrast mode |
| Live updates | verdict, status, incident and toasts are `aria-live` regions |
| Reduced motion | animations and smooth scrolling are off with `prefers-reduced-motion` |
| Glossary | definitions appear on hover **and** keyboard focus, and are linked with `aria-describedby` |

## Modes (F080)

Customise (layout button) → Colours: **Colour-blind safe** uses the Okabe & Ito palette for
lines and levels. Contrast: **High contrast** darkens secondary text and borders; it is
switched on automatically when the system asks for more contrast (`prefers-contrast: more`).

## Not tested

- With real screen readers (VoiceOver, NVDA, TalkBack). The markup follows the ARIA
  patterns (tabs, dialog, combobox + listbox, tooltip), but nobody has listened to it yet.
- Plotly charts are not accessible to screen readers; the same information is in the event
  list, the alert list and the table (and the CSV export).
- Hindi and Telugu (F082) are draft translations of the main screen only.
