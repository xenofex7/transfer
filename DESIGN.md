# Design System - transfer

> Self-hosted file transfer service. UI ist **technisch-präzise, ohne Marketing-Bullshit** - das Tool macht eine Sache (Datei rein, Link raus) und das UI hat die Pflicht, dabei nicht im Weg zu stehen.
>
> Basis: Petrol-Baseline (`~/Development/claude-stuff/design/baseline.md`). Token-Namen und Struktur stammen aus der Baseline, Werte und Komponenten sind projektspezifisch. Marketing-Komponenten der Baseline (Pricing, Testimonials, Hero-Mockup, CTA-Band, Feature-Grids, Avatare) nutzt transfer nicht, sie sind bewusst entfernt.
>
> **Für Codegen + Audits:** Die maschinenlesbare Token-Schicht steht im JSONC-Block unter `## Tokens (machine-readable)`. `/audit-design` liest diesen Block, nicht die Prosa. Bei Änderungen beide synchron halten, der Block gewinnt im Zweifel.

## Design Principles

1. **Technisch-präzise, ohne Marketing-Bullshit.** Klartext, keine Hero-Claims, keine "simply secure fast"-Phrasen im UI. Wenn ein Wort weg kann, ist es weg.
2. **Das UI darf den User nicht abschrecken.** Bei einem Self-hosted-Tool sieht "selbstgebastelt" schnell wie "unsicher" aus. Konsequent ausgeführte Tokens sind die Antwort, nicht Dekoration.
3. **Petrol = Marke, schwarz = Action.** Die 7-Step-Petrol-Skala trägt Links, Focus-Rings, Akzent-Surfaces und Wayfinding. Primary CTA ist **schwarz im Light-Theme** und invertiert im Dark-Theme zu **weisser Background mit dunklem Text**. Petrol wird **nie** die Ruhefarbe einer Action.
4. **System-Theme als Default.** `prefers-color-scheme` entscheidet, der explizite Toggle überschreibt, der Operator kann einen Default setzen. Beide Themes sind gleichwertig durchgestaltet.
5. **Die Display-Grenze ist strikt.** Display ist eine Rolle, keine Schrift: Inter 600 mit negativem Tracking für H1-H3. Body borgt sich diese Behandlung nie.
6. **Tokens sind Pflicht, wo sie existieren.** Farbe, Typo, Spacing, Radius, Schatten und Motion kommen aus dem Token-Block. Komponentenmasse, die der Block nicht trägt (Höhen, Icon-Grössen, Paddings), stehen als px-Wert in der Komponenten-Spec.
7. **Default und Active führen, Hover ist dezent.** Jede Komponente hat Default und Pressed-State. transfer ist ein Desktop-lastiges Werkzeug und nutzt zusätzlich einen dezenten Pointer-Hover (siehe `Motion` unter `Hover`). Hover ist nie der einzige Hinweis auf eine Affordance, weil es ihn auf Touch nicht gibt.
8. **Knappheit macht ein Signal.** Im Light-Theme ist die Footer-Leiste die einzige dunkle Fläche.

## Tokens (machine-readable)

```jsonc
{
  "$id": "design-tokens/transfer",
  "meta": {
    "accent": "petrol",
    "themeStrategy": "system-default + data-theme override + operator default",
    "fontStrategy": "Inter 600 (-0.04em) as Display substitute"
  },
  "requirements": {
    "darkMode": true,
    "responsive": true,
    "tokensOnly": true
  },
  "colors": {
    "canvas": "#ffffff",
    "primary": "#0a0a0a",
    "primary-active": "#242424",
    "on-primary": "#ffffff",
    "surface": "#ffffff",
    "surface-card": "#f0f8fb",
    "surface-soft": "#e0f2f7",
    "surface-strong": "#e5e7eb",
    "hairline": "rgb(0 0 0 / 0.10)",
    "hairline-soft": "rgb(0 0 0 / 0.06)",
    "ink": "#0a0a0a",
    "ink-soft": "#404040",
    "ink-mute": "#6b6b6b",
    "surface-dark": "#032e3a",
    "surface-dark-elevated": "#052838",
    "surface-dark-soft": "#042634",
    "hairline-dark": "rgb(255 255 255 / 0.08)",
    "hairline-soft-dark": "rgb(255 255 255 / 0.05)",
    "on-dark": "#ffffff",
    "on-dark-soft": "rgb(255 255 255 / 0.82)",
    "on-dark-mute": "rgb(255 255 255 / 0.68)",
    "link": "#086480",
    "link-dark": "#5bbcd2",
    "focus-ring": "#0d8fb1",
    "selection-bg": "#e0f2f7",
    "selection-text": "#032e3a",
    "scrollbar-thumb": "#0d8fb1",
    "scrollbar-hover": "#086480",
    "emphasis-hover-dark": "#9dd6e4",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#c0392b",
    "danger-dark": "#ef7d70",
    "petrol": {
      "50": "#e0f2f7",
      "100": "#9dd6e4",
      "200": "#5bbcd2",
      "400": "#0d8fb1",
      "600": "#086480",
      "800": "#054757",
      "900": "#032e3a"
    }
  },
  "typography": {
    "fontFamily": {
      "display": "Inter",
      "body": "Inter",
      // Projekt-Override: kein Webfont für Code, System-Monospace
      "mono": "ui-monospace, SFMono-Regular, \"SF Mono\", Menlo, Consolas, monospace",
      "fallback": "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif"
    },
    "scale": {
      "display-xl": { "size": 64, "weight": 600, "lineHeight": 1.05, "tracking": -2,   "face": "display" },
      "display-lg": { "size": 48, "weight": 600, "lineHeight": 1.1,  "tracking": -1.5, "face": "display" },
      "display-md": { "size": 36, "weight": 600, "lineHeight": 1.15, "tracking": -1,   "face": "display" },
      "display-sm": { "size": 28, "weight": 600, "lineHeight": 1.2,  "tracking": -0.5, "face": "display" },
      "title-lg":   { "size": 22, "weight": 600, "lineHeight": 1.3,  "tracking": -0.3, "face": "body" },
      "title-md":   { "size": 18, "weight": 600, "lineHeight": 1.4,  "tracking": 0,    "face": "body" },
      "title-sm":   { "size": 16, "weight": 600, "lineHeight": 1.4,  "tracking": 0,    "face": "body" },
      "body-md":    { "size": 16, "weight": 400, "lineHeight": 1.5,  "tracking": 0,    "face": "body" },
      "body-sm":    { "size": 14, "weight": 400, "lineHeight": 1.5,  "tracking": 0,    "face": "body" },
      "caption":    { "size": 13, "weight": 500, "lineHeight": 1.4,  "tracking": 0,    "face": "body" },
      "eyebrow":    { "size": 12, "weight": 500, "lineHeight": 1.0,  "tracking": "0.1em", "transform": "uppercase", "color": "petrol-600", "face": "body" },
      "code":       { "size": 14, "weight": 400, "lineHeight": 1.5,  "tracking": 0,    "face": "mono" },
      "button":     { "size": 14, "weight": 600, "lineHeight": 1.0,  "tracking": 0,    "face": "body" },
      "nav-link":   { "size": 14, "weight": 500, "lineHeight": 1.4,  "tracking": 0,    "face": "body" }
    }
  },
  "motion": {
    "duration": { "instant": 100, "fast": 150, "base": 250 },
    "easing":   { "standard": "cubic-bezier(0.4, 0, 0.2, 1)" }
  },
  "spacing": { "base": 4, "xxs": 4, "xs": 8, "sm": 12, "md": 16, "lg": 24, "xl": 32, "xxl": 48, "section": 96 },
  "radius":  { "xs": 4, "sm": 6, "md": 8, "lg": 12, "xl": 16, "pill": 9999, "full": 9999 },
  "shadow":  {
    "sm": "0 1px 2px rgba(0,0,0,0.05)",
    "md": "0 4px 12px rgba(0,0,0,0.08)"
  },
  // min-width Breakpoints in px. Mobile = Default (< 768).
  "breakpoints": { "tablet": 768, "desktop": 1024, "wide": 1440 },
  // Projekt-Override: Werkzeug-Layouts statt 1200px-Marketing-Container
  "container": { "page": 720, "narrow": 460, "shell": 1100 }
}
```

## Colors

### Brand Scale (Petrol)

A 7-step Türkis-Richtung-Blau scale. Each step has a defined role - don't reach for a Petrol shade unless its role matches.

| Token | Value | Role |
|---|---|---|
| `{colors.petrol-50}` | #e0f2f7 | Selection highlight background, surface-card tint base |
| `{colors.petrol-100}` | #9dd6e4 | Dark-theme emphasis hover, active nav text (dark), footer link hover |
| `{colors.petrol-200}` | #5bbcd2 | Inline links on dark surfaces, brand-emphasis badge background |
| `{colors.petrol-400}` | #0d8fb1 | **Primary accent** - scrollbar thumb, focus ring, nav tint, dropzone active border, emphasis-card border |
| `{colors.petrol-600}` | #086480 | Inline links on light surfaces, eyebrow text, scrollbar hover, active nav text (light) |
| `{colors.petrol-800}` | #054757 | Deep accent surfaces |
| `{colors.petrol-900}` | #032e3a | Dark-theme canvas, footer bar background |

### Action Layer (Black, not Petrol)

- **Primary** (`{colors.primary}` - #0a0a0a): All primary CTAs. Identical to `{colors.ink}`.
- **Primary Active** (`{colors.primary-active}` - #242424): Press and hover state for primary buttons.
- **On Primary** (`{colors.on-primary}` - #ffffff): Text on primary buttons.

**On dark surfaces** the action layer inverts: primary renders with `{colors.on-dark}` background and `{colors.surface-dark}` text; press/hover shifts to `{colors.emphasis-hover-dark}` (Petrol-100). Petrol does **not** become the action color in dark.

### Surface (Light)

- **Canvas** (`{colors.canvas}` - #ffffff): The default page floor.
- **Surface** (`{colors.surface}` - #ffffff): Modal bodies, secondary buttons, toasts. Same hex as canvas, separate token so dark can flip it independently.
- **Surface Card** (`{colors.surface-card}` - #f0f8fb): Petrol-50 tint. Every `card`, the dropzone, the app-shell sidebar.
- **Surface Soft** (`{colors.surface-soft}` - #e0f2f7 = Petrol-50): Nav-pill-group background, table header, ghost-control hover. One step stronger than surface-card, so it still reads on a card. ink-mute on it: 4.62:1 (AA).
- **Surface Strong** (`{colors.surface-strong}` - #e5e7eb): Disabled button background.
- **Hairline** (`{colors.hairline}` - `rgb(0 0 0 / 0.10)`): Input borders, secondary-button borders, dropzone dash.
- **Hairline Soft** (`{colors.hairline-soft}` - `rgb(0 0 0 / 0.06)`): Card outlines, table row dividers, sidebar border.

### Surface (Dark)

Full inversion when the dark theme is active. In the light theme only the footer bar uses this set.

- **Canvas Dark** (`{colors.surface-dark}` - #032e3a): Dark canvas, footer bar.
- **Surface Dark Elevated** (`{colors.surface-dark-elevated}` - #052838): Cards and surfaces inside the dark canvas.
- **Surface Dark Soft** (`{colors.surface-dark-soft}` - #042634): Secondary surfaces inside the dark canvas.
- **Hairline Dark** (`{colors.hairline-dark}` - `rgb(255 255 255 / 0.08)`): Border tone on dark surfaces.
- **Hairline Soft Dark** (`{colors.hairline-soft-dark}` - `rgb(255 255 255 / 0.05)`): `hairline-soft` in the dark theme.

### Theme Activation

- **Default (no `data-theme` attribute):** Theme follows `prefers-color-scheme`.
- **Explicit override:** `data-theme="light"` or `data-theme="dark"` on `<html>` pins the theme. The toggle persists in `localStorage` under the key **`transfersh_theme`** (legacy name, bewusst namespaced) with values `light` | `dark` | `system`.
- **Operator default:** `<html data-theme-default="...">` carries the default from the admin settings. It applies when `localStorage` holds no valid value.
- **Token scoping:** Dark overrides are defined in both `:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }`.
- **Initial flash:** The attribute is set before first paint by the inline bootstrap script (`server/handlers.go::themeBootstrap`), rendered into every template via `{{theme_bootstrap}}`.

### Text (Light)

- **Ink** (`{colors.ink}` - #0a0a0a): Headlines and emphasis text.
- **Ink Soft** (`{colors.ink-soft}` - #404040): Default running text.
- **Ink Mute** (`{colors.ink-mute}` - #6b6b6b): Secondary text, captions, meta, hints.

### Text (Dark)

- **On Dark** (`{colors.on-dark}` - #ffffff): Headlines and emphasis on dark surfaces.
- **On Dark Soft** (`{colors.on-dark-soft}` - `rgb(255 255 255 / 0.82)`): Body text on dark surfaces.
- **On Dark Mute** (`{colors.on-dark-mute}` - `rgb(255 255 255 / 0.68)`): Secondary text on dark surfaces, footer bar text.

### Interaction Tokens

- **Link** (`{colors.link}` - #086480 = Petrol-600): Inline links on light surfaces (6.68:1 on canvas).
- **Link Dark** (`{colors.link-dark}` - #5bbcd2 = Petrol-200): Inline links in the dark theme (6.57:1 on surface-dark).
- **Focus Ring** (`{colors.focus-ring}` - #0d8fb1 = Petrol-400): Focus-visible outline.
- **Selection** (`{colors.selection-bg}` / `{colors.selection-text}`): Petrol-50 / Petrol-900.
- **Scrollbar** (`{colors.scrollbar-thumb}` / `{colors.scrollbar-hover}`): Petrol-400 / Petrol-600.
- **Emphasis Hover (dark)** (`{colors.emphasis-hover-dark}` - #9dd6e4 = Petrol-100): Hover/press of the inverted primary.

### Semantic

- **Success** (`{colors.success}` - #10b981): Confirmation states, copied-state icons.
- **Warning** (`{colors.warning}` - #f59e0b): Warning callouts.
- **Danger** (`{colors.danger}` - #c0392b): Validation errors, destructive actions.
- **Danger Dark** (`{colors.danger-dark}` - #ef7d70): Danger in the dark theme (5.38:1 on surface-dark).

Success and warning never colour message text (2.54:1 / 2.15:1 on canvas): status copy stays in `{colors.ink-soft}`, the semantic colour sits on the border or icon.

## Typography

### Font Family

Inter carries both roles, served locally (`/fonts/inter-*.woff2`, `font-display: optional`). **Display** is Inter 600 with negative tracking; **Body** is Inter 400-600 with neutral tracking. Code uses the system monospace stack (`{typography.fontFamily.mono}`) - transfer ships no code webfont.

### Hierarchy

The scale is the baseline scale. transfer is a tool, not a marketing site, so headlines sit one step lower than on a landing page:

| Element | Token | Notes |
|---|---|---|
| `h1`, `.hostname` | `{typography.display-md}` (36px) | Page headline, instance hostname on the homepage |
| `h2`, `.page-title` | `{typography.display-sm}` (28px) | App-shell page titles |
| `h3` | 22px Display, tracking -0.3px | Section heads inside cards |
| `h4`, `.settings-section-title` | `{typography.title-md}` (18px) | Inter, not Display |
| `.not-found h1` | `{typography.display-xl}` (64px) | The single 64px use: the 404 code |
| Running text | `{typography.body-md}` / `{typography.body-sm}` | 16px default, 14px in cards, tables, toasts |
| Labels, meta, hints | `{typography.caption}` (13px) | Field labels, badges, file names |
| Table header | 12px / 500 / uppercase / 0.08em | `ink-mute` on `surface-soft` |
| Code | `{typography.code}` | Links, tokens, CLI examples |

### Principles

Display weight stays at 600 - never 700, never 500. Display without negative tracking reads as off-brand. Nothing below 12px: the scale ends at `{typography.eyebrow}`.

## Layout

### Spacing System

- **Base unit:** 4px.
- **Tokens:** `{spacing.xxs}` 4 · `{spacing.xs}` 8 · `{spacing.sm}` 12 · `{spacing.md}` 16 · `{spacing.lg}` 24 · `{spacing.xl}` 32 · `{spacing.xxl}` 48 · `{spacing.section}` 96.
- **Card internal padding:** `{spacing.xl}`.
- **Stack gap between cards:** `{spacing.xl}` on public pages, `{spacing.lg}` in the app shell.

### Public Pages

Upload, download, login, secret and 404 pages share one single-column composition:

- **`page`** - max-width `{container.page}` (720px), centered, padding `{spacing.xxl}` top, `{spacing.md}` sides, 80px bottom (clears the fixed footer bar), vertical gap `{spacing.xl}`.
- **`page-narrow`** - max-width `{container.narrow}` (460px) for login, TOTP and 2FA flows.
- **`hero`** - centered: logo (72px high, max 420px wide), hostname in `display-md`, tagline in `body-md` / `ink-mute`.
- **Floating controls** - `theme-toggle` fixed top-right (`{spacing.md}` from the edges); `top-auth` cluster (13px, user name + sign-in/out link) left of it.

### App Shell (signed-in admin/account area)

- **Sidebar left, content right.** Sidebar 256px, `{colors.surface-card}` background, 1px `{colors.hairline-soft}` right border. Top to bottom: brand row (56px, logo, hairline bottom border), nav list (flex 1, scrollable), foot block (hairline top border: username + sign-out icon, version + GitHub icon).
- **Nav items:** Inter 14px / 500, icon 16px + label, padding 8px 12px, `{rounded.md}`. Inactive `{colors.ink-mute}`; hover `{colors.surface-soft}` + `{colors.ink}`; active = `petrol-400` at 12% with `petrol-600` text (light) / `petrol-100` (dark). Petrol carries wayfinding, black stays reserved for CTAs.
- **Content column:** max `{container.shell}` (1100px) centered, page padding `{spacing.lg}`/`{spacing.xl}`, cards stack with `{spacing.lg}` gaps. Page head = `page-title` + muted count/subtitle inline.
- **Mobile (< 768px):** sidebar becomes an off-canvas drawer (translateX) behind a 50% black overlay; a sticky 56px topbar carries the hamburger + logo. Close via X, overlay click or Escape.
- **No footer bar inside the shell** - version and GitHub live in the sidebar foot.

## Elevation & Depth

| Level | Treatment | Use |
|---|---|---|
| Flat | No shadow, no border | Page canvas |
| Soft hairline | 1px `{colors.hairline}` | Inputs, secondary buttons, icon buttons |
| Card surface | `{colors.surface-card}` + 1px `{colors.hairline-soft}` | Every `card`, dropzone |
| `{shadow.sm}` | `0 1px 2px rgba(0,0,0,0.05)` | Active category-tab inside the pill group |
| `{shadow.md}` | `0 4px 12px rgba(0,0,0,0.08)` | Toast, tooltip, modal |

No heavy shadows, no neumorphism, no glassmorphism. Overlays (modal backdrop, sidebar overlay) use black at 50%.

## Shapes

| Token | Value | Use |
|---|---|---|
| `{rounded.xs}` | 4px | Reserved, currently unused |
| `{rounded.sm}` | 6px | Tooltip, focus-ring corners |
| `{rounded.md}` | 8px | Buttons, inputs, nav items, category tabs, toasts |
| `{rounded.lg}` | 12px | Cards, dropzone, modal, table wrapper |
| `{rounded.xl}` | 16px | Reserved, currently unused |
| `{rounded.pill}` | 9999px | Nav-pill-group, badges, progress bars |
| `{rounded.full}` | 9999px | Circular icon buttons (theme toggle, toast close) |

## Motion

The system is quiet: no entrance choreographies, no parallax. Motion confirms that an interaction happened.

| Token | Value | Use |
|---|---|---|
| `{motion.duration.instant}` | 100ms | Press and hover colour shifts |
| `{motion.duration.fast}` | 150ms | Focus ring, modal fade |
| `{motion.duration.base}` | 250ms | Sidebar drawer, toast enter/leave |
| `{motion.easing.standard}` | `cubic-bezier(0.4, 0, 0.2, 1)` | Every transition |

- **Press:** primary shifts to `{colors.primary-active}`. Nothing scales, nothing lifts.
- **Hover (Projektregel):** transfer adds a quiet pointer hover, limited to three patterns:
  - **Outlined controls** (secondary button, icon button, theme toggle, copy button): border and text shift to `{colors.ink}`.
  - **Ghost controls** (sidebar nav, sidebar icons, topbar menu, toast/modal close): background shifts to `{colors.surface-soft}` or `{colors.surface-card}`, text to `{colors.ink}`.
  - **Primary and danger buttons:** hover shows the press state early (`primary-active`, danger fill).
  Text links underline on hover; footer links shift to `{colors.petrol-100}`; the dropzone border shifts to `{colors.petrol-400}`; table rows tint. Nothing else changes on hover - no lifts, no shadows, no scale.
- **Focus:** 2px `{colors.focus-ring}` outline, offset 2px (4px on buttons and the dropzone), never animated away.
- **`prefers-reduced-motion`:** mandatory - all transitions and animations collapse.

## Voice & Tone

- **UI strings are English.** The tool is used primarily in English; docs and code comments may be German.
- **Plain over clever.** Name the function: "Upload", "Copy link", "Delete user".
- **No marketing language anywhere in the UI.** No hero claims, no taglines that sell.
- **No trailing period on single-line UI strings.** Body copy keeps its sentences.

| Context | Pattern | Example |
|---|---|---|
| Primary CTA | Verb + object, max 3 words | "Create secret" |
| Error | What happened + object | "Upload failed (413): file.zip" |
| Success toast | Past tense, short | "Options saved" |
| Neutral toast | State, short | "Link copied" |

Dates `TT.MM.JJJJ`, straight quotes only, plain hyphens, URLs English.

## Components

### Buttons

**`button-primary`** (`.btn-primary`, `.button.primary`) - Background `{colors.primary}`, text `{colors.on-primary}`, `{typography.button}`, padding 12px × 20px, height 40px, `{rounded.md}`. Hover and press: `{colors.primary-active}`. Inverts on dark (see Action Layer).

**`button-secondary`** (`.btn-secondary`, `.button`) - Background `{colors.surface}`, text `{colors.ink}`, 1px `{colors.hairline}` border, same metrics as primary. Hover: border `{colors.ink}`.

**`button-danger`** (`.btn-danger`) - Outlined: transparent background, `{colors.danger}` text and border. Hover and press fill with `{colors.danger}`, text `{colors.on-primary}`. Only for destructive actions, always behind a `dialog`.

**`button-icon-circular`** (`.theme-toggle`, `.icon-btn`, `.upload-copy`) - 36 × 36px, `{rounded.full}`, hairline border, 16px icon in `{colors.ink-mute}`. Floating (theme toggle) on `{colors.surface}`, inline (table actions, copy) on transparent. `.icon-btn.danger` uses `{colors.danger}` and fills on hover. The toast close button uses the same shape at 24px.

**`text-link`** (`a`, `.link`) - `{colors.link}` / `{colors.link-dark}`, underline on hover. `.link` is the button-as-link variant for inline actions ("browse").

### Cards & Surfaces

**`card`** - Background `{colors.surface-card}`, 1px `{colors.hairline-soft}` border, `{rounded.lg}`, padding `{spacing.xl}`. The one container for every content block.

**`card-emphasis`** - A card that needs attention (recovery codes, 2FA result). Border `{colors.petrol-400}`, background `petrol-400` at 6% over `{colors.surface}`. Petrol as accent surface, never as action.

**`dropzone`** - The upload surface on the homepage, built on `card`. Min-height 260px, 1.5px dashed `{colors.hairline}` border, centered prompt in `{colors.ink-mute}`. Hover/focus: border `{colors.petrol-400}`. Drag-active: border `{colors.petrol-400}`, background `petrol-400` at 6% over `{colors.surface-card}`.

**`qr-code`** - 240px image, 12px padding, hairline border, `{rounded.md}`. Background stays white in both themes (`{colors.on-dark}`, the theme-independent white) so scanners get full contrast.

**`data-table`** (`.admin-table`, `.users-table`) - `{typography.body-sm}`, cells 12px × 10px, rows divided by `{colors.hairline-soft}`, sticky header in the table-header style on `{colors.surface-soft}`. Wrapped in a `card` with zero padding and horizontal scroll.

### Inputs & Forms

**`text-input`** - Background `{colors.canvas}`, text `{colors.ink}`, `{typography.body-md}`, `{rounded.md}`, padding 10px × 14px, height 40px, 1px `{colors.hairline}` border. The visible label is mandatory (hairline alone is below 3:1).

**`text-input-focused`** - Border shifts to `{colors.ink}` plus a 3px `focus-ring` halo at 25%.

**`field-error`** - Every form with validated fields carries `novalidate`; native validity bubbles never appear. The invalid input gets `aria-invalid="true"` and a `{colors.danger}` border; the message sits under it in `{typography.caption}` / `{colors.danger}`, linked via `aria-describedby`. The first invalid field receives focus; the message clears on the next input.

**`file-picker`** - The native `<input type="file">` stays hidden. Visible is a `button-secondary` "Choose file" plus the file name (or "No file chosen") in `{typography.caption}` / `{colors.ink-mute}`, truncated with an ellipsis. On the homepage the dropzone is the picker. Oversized files are rejected client-side with a `toast-danger`.

### Navigation

**`nav-pill-group`** + **`category-tab`** - Upload / Secret switcher on the homepage. Wrapper: `{colors.surface-soft}`, padding 6px, `{rounded.pill}`. Tab: padding 8px × 14px, `{rounded.md}`, inactive `{colors.ink-mute}`. Active: `{colors.canvas}` background, `{colors.ink}` text, `{shadow.sm}`.

**`sidebar`** - See `App Shell`.

### Feedback

**`toast`** - Background `{colors.surface}`, 1px hairline border, `{rounded.md}`, padding 12px × 16px, `{shadow.md}`. Leading 16px status icon, single-line message in `{typography.body-sm}` / `{colors.ink}`, optional 24px close button. Max width 420px; on mobile it stretches to viewport minus 16px gutters.

- **`toast-success`** / **`toast-warning`** / **`toast-danger`** - Icon and 3px left border in the semantic colour.
- **`toast-neutral`** - No left border, icon in `{colors.ink-mute}`.

Stack bottom-right on desktop (`{spacing.lg}` from the edges, above the footer bar), bottom-center on mobile (< 768px). Max 3 visible. Auto-dismiss 4s (success, neutral), 6s (warning), never for danger. Hover pauses the timer. No toasts on page load.

**`tooltip`** - Declared with `data-tooltip="..."`, never the native `title` attribute. One shared bubble: background `{colors.ink}`, text `{colors.canvas}`, 12px / 500, padding 4px × 8px, `{rounded.sm}`, `{shadow.md}`, max-width 280px. Appears above the trigger, flips below near the top edge, no arrow, no animation. Also on keyboard focus; hides on pointer down, click, scroll or Escape. Icon-only controls carry an `aria-label` too.

**`dialog`** - Replaces native `confirm()` / `alert()`. Shell `modal-backdrop` + `modal`: `{colors.surface}`, hairline border, `{rounded.lg}`, `{shadow.md}`. Sizes: small (`modal-sm`, 420px) for confirmations, default (680px) for the changelog. Title `{typography.title-md}`, message `{typography.body-md}`, footer with cancel (`button-secondary`) left and action (`button-primary` or `button-danger`) right. Escape and backdrop click cancel, Tab is trapped, focus returns to the trigger. API: `dialog.confirm({...})`, `dialog.alert({...})`; forms route their submit through it with `data-confirm`.

### Tags / Badges

**`badge-pill`** (`.users-badge`, `.heartbeat-pill`) - Background `{colors.surface-card}` or `{colors.petrol-200}` for brand emphasis, text `{colors.ink}`, `{typography.caption}`, `{rounded.pill}`, padding 4px × 12px.

**`eyebrow`** - `{typography.eyebrow}` in `{colors.petrol-600}`. Used for section labels inside the changelog modal.

### Footer

**`footer-bar`** (`.footer`) - A slim bar fixed to the bottom of every public page. Background `{colors.surface-dark}`, 1px `{colors.hairline-dark}` top border, padding 10px × `{spacing.md}`, 12px text in `{colors.on-dark-mute}`. Three-column grid: version left (opens the changelog when signed in), contact/privacy links center, "source on github" right. Links hover to `{colors.petrol-100}`. In the light theme it is the only dark surface. Not rendered inside the app shell.

## Do's and Don'ts

### Do
- Reserve `{colors.primary}` for primary CTAs and headlines.
- Put every content block in a `card`; use `card-emphasis` only when the user must not miss it.
- Use `dialog`, `tooltip`, `field-error`, `file-picker` and `toast` instead of browser defaults.
- Reference tokens everywhere. A value missing from the token block is a spec gap, not a licence to inline.

### Don't
- Don't use Petrol as the resting colour of an action.
- Don't introduce a second accent palette. Semantic colours appear only in their semantic role.
- Don't set Display weight above 600 or drop the negative tracking.
- Don't use a radius above `{rounded.xl}` (16px) on any container.
- Don't add dark surfaces in the light theme beyond the footer bar.
- Don't add hover styling beyond the three patterns in `Motion` - no lifts, shadows or scale on hover.
- Don't go below 12px type.
- Don't use native browser dialogs or hints: no `confirm()`, `alert()`, `prompt()`, no `title` for hover text, no validity bubbles, no visible native file control.
- No marketing illustrations, animated gradients, glassmorphism, neon glow, pastel or multicolour icon sets.

## Responsive Behavior

### Breakpoints

| Name | Width | Key changes |
|---|---|---|
| Mobile | < 768px | App shell: sidebar → off-canvas drawer + topbar. Public pages: upload list and option grids go 1-up, top-auth hides the user name, hostname drops to 22px, tables tighten, toasts move bottom-center |
| Tablet | 768-1024px | App shell with fixed sidebar; public pages unchanged (720px column fits) |
| Desktop | 1024-1440px | Same as tablet |
| Wide | > 1440px | Same, more outer breathing room |

Mobile rules use `@media (max-width: 767px)`, tablet and up `@media (min-width: 768px)`. No other breakpoint values.

### Touch Targets
- `button-primary`, `button-secondary`, `text-input`: 40px high.
- `button-icon-circular`: 36 × 36.
- The toast close button (24px) is deliberately below target: the toast dismisses itself.
- New components meet 44 × 44 or earn an entry here.

## Accessibility

Contrast pairs and ratios are taken from the baseline (`Accessibility` → `Measured Contrast`); the token values are identical. Project specifics:

- **Language:** `<html lang="en">` (UI is English).
- **Focus ring:** always visible. `outline: none` only with a visible replacement (inputs: border + halo).
- **Forms:** every field has a label wired with `for`/`id`; errors via `aria-describedby`.
- **Icon-only buttons:** `aria-label` plus `data-tooltip`.
- **Sandboxed previews:** `<iframe>` carries a `title` - this is an accessible name, not a hover hint, and the only allowed `title`.
- No colour as sole information carrier, no `tabindex` above 0.

## Iteration Guide

1. One component at a time; reference its key (`{component.dropzone}`, `{component.toast}`).
2. Variants (`-active`, `-emphasis`, `-danger`) live next to their base component.
3. Token refs everywhere, never inline hex.
4. Document Default and Active; Hover only within the three patterns in `Motion`.
5. When in doubt about emphasis: bigger Display before bolder Display.
6. A gap every project would hit goes upstream into the baseline first, then into this file.

## Known Gaps

- Inter 600 stands in for a Display face. A licensed face would keep weight 600 and the tracking.
- Petrol mid-stops 300/500/700 are intentionally undefined.
- Hairlines use rgba notation (composites cleanly on Petrol-tinted surfaces).
- No empty-state component spec yet; empty admin lists use a plain `card` with muted text.
- Media previews (image, video, audio, markdown, sandbox) render the file's own chrome inside a `card`; their internals are out of scope.
