# Design System - transfer

> Self-hosted file transfer service. UI ist **technisch-präzise, ohne Marketing-Bullshit** - das Tool macht eine Sache (Datei rein, Link raus) und das UI hat die Pflicht, dabei nicht im Weg zu stehen.
>
> Basis: Petrol-Baseline (Modern-SaaS-Struktur + Petrol-Akzentpalette). Werte und Don'ts projektspezifisch angepasst.

## Design Principles

1. **Technisch-präzise, ohne Marketing-Bullshit.** Klartext, keine Hero-Claims, keine „simply secure fast"-Phrasen im UI. Wenn ein Wort weg kann, ist es weg.
2. **Das UI darf den User nicht abschrecken.** Bei einem Self-hosted-Tool sieht „selbstgebastelt" schnell wie „unsicher" aus. Konsequent ausgeführte Tokens sind die Antwort, nicht Dekoration.
3. **Petrol = Marke, schwarz = Action.** Die 7-Step-Petrol-Skala (Türkis Richtung Blau) trägt Links, Focus-Rings, Akzent-Surfaces. Primary CTA ist **schwarz im Light-Theme** und invertiert im Dark-Theme zu **weisser Background mit dunklem Text** (siehe `Action Layer` in Colors). Petrol wird **nie** zur Action-Farbe - der Black-vs-Petrol-Split bleibt in beiden Themes erhalten.
4. **System-Theme als Default.** Kein voreingestelltes Light oder Dark - `prefers-color-scheme` entscheidet, der explizite Toggle überschreibt. Beide Themes sind gleichwertig durchgestaltet, kein Theme ist „Zweitklasse".
5. **Display-Typo trägt die Marke.** Inter 600 mit negativem Letter-Spacing (-0.04em) für H1-H3. Inter Body für alles andere. Strikt: nie Body in Display, nie Display in Body.

## Overview

`transfer` ist ein Browser-UI für ein selbst gehostetes File-Transfer-Tool: Upload, Share-Link, Account-/Admin-Bereich. Es ist **kein Marketing-Frontend** - jede Seite ist ein Werkzeug. Die Petrol-Baseline liefert die visuelle Grammatik (Token-System, Spacing, Radius-Hierarchie, Footer-Klammer), die Inhalte sind nüchtern.

Der **Accent ist Petrol** - eine 7-Step-Skala Türkis Richtung Blau (`{colors.petrol-400}` = #0d8fb1 als Primary-Accent). Petrol trägt Links, Focus-Rings, Eyebrows, dunkle Surfaces. Der Primary-CTA bleibt **schwarz** (`{colors.primary}` = #0a0a0a) im Light-Theme und invertiert im Dark-Theme zu weisser Background mit `surface-dark` Text - Petrol wird nie zur Action-Farbe.

**Theme-Strategie:** System-Preference ist Default (`:root` ohne `data-theme` folgt `prefers-color-scheme`). Der Toggle setzt explizit `data-theme="light"` oder `data-theme="dark"` und überschreibt die System-Preference. Beide Themes sind vollständige Inversionen, nicht „Dark mit anderem Akzent".

Type voice splits cleanly into two roles: **Display** (Inter 600 mit -0.04em letter-spacing) für H1-H3 und Hero-Headlines, **Inter Body** für alles andere - body, Buttons, Nav, Captions. Drop-in-Alternativen für Display: Manrope 700, Geist 600 - immer mit dem negativen Tracking, das Tracking ist die Voice, nicht die Schrift.

Der **Footer flippt** auf `{colors.surface-dark}` (#032e3a = Petrol-900) als visuelle Klammer am Seitenende - im Light-Theme die einzige dunkle Surface, im Dark-Theme deckungsgleich mit dem Canvas.

**Key Characteristics:**
- Primary CTA ist **schwarz im Light** (`{colors.primary}` = #0a0a0a) und **invertiert im Dark** (weisse Background, `surface-dark` Text, Hover Petrol-100). Buttons sind `{rounded.md}` (8px), Label-Weight 600.
- **Display**-Typo (Inter 600 mit -0.04em letter-spacing) für H1-H3. Inter Body für Rest.
- Petrol-tinted card surfaces (`{colors.surface-card}` - #f0f8fb im Light, Petrol-900-Variante im Dark) für Content-Cards.
- **Keine Marketing-Illustrationen.** Wenn das UI ein Bild zeigt, ist es ein Asset (Logo, Datei-Icon, Avatar) - keine dekorativen Renderings.
- Footer in Petrol-900 (`{colors.surface-dark}` - #032e3a) als visuelle Klammer.
- Spacing-Rhythmus `{spacing.section}` (96px) zwischen Major-Bands.
- Border-Radius hierarchisch: `{rounded.md}` (8px) Buttons + Inputs, `{rounded.lg}` (12px) Cards, `{rounded.xl}` (16px) Hero-Container, `{rounded.pill}` Nav-Pill-Group + Badges, `{rounded.full}` Avatare + Icon-Buttons.

**Don'ts (projektspezifisch):**
- Kein „Hobby-Tool"-Look. Inkonsequente Spacings, ungefilterte Default-Browser-Inputs, halbherzige Hover-States - alles, was Vertrauen kostet.
- Keine Marketing-Hero-Claims im UI („Simple. Secure. Fast.").
- Keine animierten Gradients, kein Glassmorphism, kein Neon-Glow.
- Keine Pastell-Avatare oder bunten Icon-Sets.

## Colors

### Brand Scale (Petrol)

A 7-step Türkis-Richtung-Blau scale. Each step has a defined role - don't reach for a Petrol shade unless its role matches.

| Token | Value | Role |
|---|---|---|
| `{colors.petrol-50}` | #e0f2f7 | Selection highlight background, surface-card tint base |
| `{colors.petrol-100}` | #9dd6e4 | Dark-theme emphasis hover |
| `{colors.petrol-200}` | #5bbcd2 | Light accent surfaces, inline pill backgrounds |
| `{colors.petrol-400}` | #0d8fb1 | **Primary accent** - inline links, scrollbar thumb, focus ring |
| `{colors.petrol-600}` | #086480 | Eyebrow text, scrollbar hover, emphasis-button hover (light theme) |
| `{colors.petrol-800}` | #054757 | Deep accent surfaces |
| `{colors.petrol-900}` | #032e3a | Dark-theme canvas, footer background, featured-tier surface |

### Action Layer (Black, not Petrol)

The primary CTA color is **black**, not Petrol. Petrol is the accent, never the action.

- **Primary** (`{colors.primary}` - #0a0a0a): All primary CTAs. Identical to `{colors.ink}` - emphasis and headline color are the same token-value pair.
- **Primary Active** (`{colors.primary-active}` - #242424): Press state for primary buttons.
- **On Primary** (`{colors.on-primary}` - #ffffff): Text on primary buttons.

**On dark surfaces** the action layer inverts: primary renders with `{colors.canvas}` background and `{colors.surface-dark}` text; press/active shifts to `{colors.emphasis-hover-dark}` (Petrol-100) on the background. Petrol does **not** become the action color in dark - the black-vs-petrol split is preserved by inverting to white-on-dark, never by promoting Petrol to CTA. See `{component.button-primary}` for the full component spec.

### Surface (Light)

- **Canvas** (`{colors.canvas}` - #ffffff): The default page floor.
- **Surface** (`{colors.surface}` - #ffffff): Standard surface (cards on white pages, modal bodies). Identical hex to canvas - separated as a token so dark-theme can flip it independently.
- **Surface Card** (`{colors.surface-card}` - #f0f8fb): A Petrol-50 tint. Feature cards, testimonial cards, default avatar fills. The tint carries a quiet Petrol breath through every card without ever feeling colored.
- **Surface Soft** (`{colors.surface-soft}` - #f8f9fa): Nav-pill-group background, very-soft section dividers. Slightly cooler than surface-card.
- **Surface Strong** (`{colors.surface-strong}` - #e5e7eb): Disabled button background, dense hairline alternative.
- **Hairline** (`{colors.hairline}` - `rgb(0 0 0 / 0.10)`): The 1px border tone on light surfaces. Used on input borders, table dividers, content card outlines.
- **Hairline Soft** (`{colors.hairline-soft}` - `rgb(0 0 0 / 0.06)`): A barely-visible divider used between sections that share the white canvas, or as the inner card border.

### Surface (Dark)

The dark theme is a complete inversion, not just a dark footer. On a light-only site, only the footer and the featured-tier card use this set.

- **Canvas Dark** (`{colors.surface-dark}` - #032e3a): Dark theme canvas. Equal to Petrol-900. Footer background on light-only sites.
- **Surface Dark** (`{colors.surface-dark-elevated}` - #052838): Card surfaces inside the dark canvas.
- **Surface Dark Soft** (`{colors.surface-dark-soft}` - #042634): Secondary surfaces inside the dark canvas.
- **Hairline Dark** (`{colors.hairline-dark}` - `rgb(255 255 255 / 0.08)`): Border tone on dark surfaces.

### Theme Activation

The baseline ships **system-preference as the default** and an **explicit toggle as the override**. The two layers are stackable - the toggle wins if present, otherwise the system setting decides.

- **Default (no `data-theme` attribute):** Theme follows `prefers-color-scheme`. Light tokens apply under `@media (prefers-color-scheme: light)`, dark tokens under `@media (prefers-color-scheme: dark)`. Most visitors never set anything; the page just matches their OS.
- **Explicit override:** `data-theme="light"` or `data-theme="dark"` on `<html>` pins the theme regardless of system preference. The toggle persists in `localStorage` (`theme` key with values `light` | `dark` | `system`) - a `system` value clears the attribute and falls back to media-query.
- **Token scoping:** Dark tokens (`{colors.surface-dark}`, `{colors.on-dark}`, etc.) are defined in both `[data-theme="dark"]` and `@media (prefers-color-scheme: dark):not([data-theme="light"])` selectors so the override truly wins.
- **Initial flash:** The theme attribute must be set **before first paint** (inline `<script>` in `<head>` reading `localStorage`), otherwise the page flashes light before flipping. This is the only inline script the baseline mandates.

On a **light-only site** the theme system is unused at the document level - dark tokens only get consumed by the footer and the featured-tier card, both of which scope their dark surface locally without depending on the global theme. A site can therefore start light-only and add full dark-mode support later without renaming tokens.

### Text (Light)

- **Ink** (`{colors.ink}` - #0a0a0a): All headlines and emphasis text. Same value as `{colors.primary}`.
- **Ink Soft** (`{colors.ink-soft}` - #404040): Default running-text color.
- **Ink Mute** (`{colors.ink-mute}` - #6b6b6b): Secondary text - sub-headings, captions, meta, fine-print.

### Text (Dark)

- **Ink Dark** (`{colors.on-dark}` - #ffffff): Headlines and emphasis text on dark surfaces.
- **Ink Dark Soft** (`{colors.on-dark-soft}` - `rgb(255 255 255 / 0.82)`): Body text on dark surfaces.
- **Ink Dark Mute** (`{colors.on-dark-mute}` - `rgb(255 255 255 / 0.68)`): Secondary text on dark surfaces.

### Interaction Tokens

- **Link** (`{colors.link}` - #0d8fb1 = Petrol-400): Inline body links. The brand keeps body type in ink-soft and lets Petrol carry interactivity.
- **Focus Ring** (`{colors.focus-ring}` - #0d8fb1 = Petrol-400): Focus-visible outline color.
- **Selection BG** (`{colors.selection-bg}` - #e0f2f7 = Petrol-50): Text selection background.
- **Selection Text** (`{colors.selection-text}` - #032e3a = Petrol-900): Text selection foreground.
- **Scrollbar Thumb** (`{colors.scrollbar-thumb}` - #0d8fb1 = Petrol-400): Scrollbar handle.
- **Scrollbar Hover** (`{colors.scrollbar-hover}` - #086480 = Petrol-600): Scrollbar handle on hover.
- **Emphasis Hover (dark)** (`{colors.emphasis-hover-dark}` - #9dd6e4 = Petrol-100): When primary inverts to white-on-dark, its hover shifts to this.

### Semantic
- **Success** (`{colors.success}` - #10b981): Confirmation states, success badges.
- **Warning** (`{colors.warning}` - #f59e0b): Warning callouts.
- **Danger** (`{colors.danger}` - #c0392b): Validation errors, destructive actions.

## Typography

### Font Family
The system runs a **Display** typeface for headlines + brand wordmark and **Inter** for everything else. Display is a geometric display face - slightly condensed, weight 600, negative letter-spacing. The baseline ships with Inter 600 as the Display substitute (universally available); projects may swap in Manrope, Geist, or a licensed custom face while keeping the weight and tracking signature. Inter (regular weights) handles body, buttons, navigation, captions, and tabular code blocks. The fallback stack walks `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif` for both families.

The split is functional:
- Display (display, 600 weight, -0.5 to -2px tracking) - h1, h2, h3
- Inter (body + UI, 400-600 weight, 0 letter-spacing) - paragraphs, labels, buttons, nav

### Hierarchy

| Token | Size | Weight | Line Height | Letter Spacing | Use |
|---|---|---|---|---|---|
| `{typography.display-xl}` | 64px | 600 | 1.05 | -2px | Homepage h1 ("The better way to schedule your meetings") - Display |
| `{typography.display-lg}` | 48px | 600 | 1.1 | -1.5px | Section heads ("Your all-purpose scheduling app") - Display |
| `{typography.display-md}` | 36px | 600 | 1.15 | -1px | Sub-section heads, card titles - Display |
| `{typography.display-sm}` | 28px | 600 | 1.2 | -0.5px | CTA-band heads, pricing tier prices - Display |
| `{typography.title-lg}` | 22px | 600 | 1.3 | -0.3px | Pricing plan names - Inter |
| `{typography.title-md}` | 18px | 600 | 1.4 | 0 | Feature card titles, intro paragraphs |
| `{typography.title-sm}` | 16px | 600 | 1.4 | 0 | Small card titles, list labels |
| `{typography.body-md}` | 16px | 400 | 1.5 | 0 | Default running-text |
| `{typography.body-sm}` | 14px | 400 | 1.5 | 0 | Footer body, fine-print |
| `{typography.caption}` | 13px | 500 | 1.4 | 0 | Badge labels, captions |
| `{typography.eyebrow}` | 12px | 500 | 1.0 | 0.1em (uppercase) | Small uppercase label above a headline - colored `{colors.petrol-600}` |
| `{typography.code}` | 14px | 400 | 1.5 | 0 | Code snippets, API examples - JetBrains Mono |
| `{typography.button}` | 14px | 600 | 1.0 | 0 | Standard button labels |
| `{typography.nav-link}` | 14px | 500 | 1.4 | 0 | Top-nav menu items |

### Principles
Display is the brand voice - every display headline uses it. Inter handles the supporting type. The boundary is strict: never put body copy in Display, never put a display headline in Inter. Display without negative letter-spacing reads as off-brand - the -0.5 to -2px tracking is part of the voice.

Display weight stays at 600 across all sizes - never 700, never 500. The middle weight is what makes Display feel modern and confident without becoming bombastic.

### Note on the Display Face
The baseline ships **Inter** at weight 600 with -0.04em letter-spacing as the Display face. It is universally available and preserves the geometric, slightly-condensed weight-600 signature the system is calibrated around. Drop-in alternatives that respect the same signature: **Manrope** at weight 700, **Geist** at weight 600, or a licensed custom display face. Whatever face is chosen, keep weight 600 (never 700) and the negative letter-spacing scale (-0.5 to -2px depending on size) - that pairing is the voice, not the font name.

## Layout

### Spacing System
- **Base unit:** 4px.
- **Tokens:** `{spacing.xxs}` 4px · `{spacing.xs}` 8px · `{spacing.sm}` 12px · `{spacing.md}` 16px · `{spacing.lg}` 24px · `{spacing.xl}` 32px · `{spacing.xxl}` 48px · `{spacing.section}` 96px.
- **Section padding:** `{spacing.section}` (96px) - the universal vertical rhythm between editorial bands.
- **Card internal padding:** `{spacing.xl}` (32px) for feature cards and pricing tier cards; `{spacing.lg}` (24px) for testimonial and product-mockup cards.
- **Gutters:** `{spacing.lg}` (24px) between cards in 3-up grids; `{spacing.md}` (16px) inside footer columns.

### Grid & Container
- **Max content width:** ~1200px centered on marketing pages.
- **Editorial body:** Single 12-column grid; hero band often uses 7/5 split (h1 left, app mockup card right).
- **Feature card grids:** 3-up at desktop, 2-up at tablet, 1-up at mobile.
- **Pricing grid:** 4-up at desktop, 2-up at tablet, 1-up at mobile.
- **Footer:** 4-column link list at desktop, wrapping to 2-up at tablet, 1-up at mobile.

### App Shell (signed-in admin/account area)
Project-specific composition built entirely from existing tokens - no new tokens.

- **Sidebar left, content right.** Sidebar 256px, `{colors.surface-card}` background, 1px `{colors.hairline}`-soft right border. Structure top to bottom: brand row (56px, logo, hairline bottom border), nav list (flex 1, scrollable), foot block (hairline top border: username + sign-out icon, version + GitHub icon in `caption` size).
- **Nav items:** Inter 14px / 500, icon 16px + label, padding 8px 12px, `{rounded.md}`. Inactive `{colors.ink-mute}`; hover `{colors.surface-soft}` + `{colors.ink}`; active = Petrol tint (`petrol-400` at 12%) with `petrol-600` text (light) / `petrol-100` (dark). The action layer (black primary) is NOT used for nav states - Petrol carries wayfinding, black stays reserved for CTAs.
- **Content column:** max 1100px centered, page padding `{spacing.lg}`/`{spacing.xl}`, cards stack with `{spacing.lg}` gaps. Page head = h2-size title + muted count/subtitle inline.
- **Mobile (<768px):** sidebar becomes an off-canvas drawer (translateX, 200ms) behind a 50% black overlay; a sticky 56px topbar carries the hamburger + logo. Close via X, overlay click or Escape.
- **No dark page footer** inside the shell - version/GitHub live in the sidebar foot.

### Whitespace Philosophy
The baseline uses generous but not excessive whitespace - section padding sits at 96px (modern-SaaS standard), and card internal padding stays at 32px. The rhythm is calibrated for fast scanning: every band has a single h1 + h2 + supporting cards, never densely packed lists. The result reads as confident-not-shouting.

## Elevation & Depth

| Level | Treatment | Use |
|---|---|---|
| Flat | No shadow, no border | Body sections, top nav, hero bands |
| Soft hairline | 1px `{colors.hairline}` border | Inputs, table dividers, occasionally on cards |
| Card surface | `{colors.surface-card}` background - no shadow | Feature cards, testimonials |
| Subtle drop shadow | Faint shadow at low alpha | Pricing tier cards, hover-elevated states (the system uses `0 1px 2px rgba(0,0,0,0.05)` and `0 4px 12px rgba(0,0,0,0.08)`) |
| Featured tier | `{colors.surface-dark}` background, no shadow needed | The featured pricing tier inverts to dark surface - color contrast does the elevation work |

The elevation philosophy is **soft and modern** - small drop shadows on elevated cards, color-block contrast for emphasis. No heavy shadows, no neumorphism, no glassmorphism.

### Decorative Depth
- Calendar widgets and product UI fragments embedded inside marketing cards carry their own internal shadows from the product UI itself - these are not system tokens, they're product chrome shown as content.
- Avatar circles in testimonial sections use `{colors.surface-card}` as default fill. No pastel set - the Petrol brand voice carries chromatic identity through accents, not through avatar fills.

## Shapes

### Border Radius Scale

| Token | Value | Use |
|---|---|---|
| `{rounded.xs}` | 4px | Almost no use - reserved for badge accents |
| `{rounded.sm}` | 6px | Small inline buttons, dropdown items |
| `{rounded.md}` | 8px | Standard CTA buttons, text inputs, category tabs |
| `{rounded.lg}` | 12px | Content cards (feature cards, testimonial cards, pricing tier cards) |
| `{rounded.xl}` | 16px | Hero app-mockup card (a slightly larger radius for the marquee component) |
| `{rounded.pill}` | 9999px | Nav-pill-group, badge pills |
| `{rounded.full}` | 9999px / 50% | Avatars, icon buttons |

### Photography Geometry
Avatar photos use `{rounded.full}` (perfect circles) at 36px or 40px. Product UI fragments inside marketing cards retain their native chrome (which often has its own internal radii - e.g., calendar grid cells, button rows). Hero illustration zones use 16:9 or 4:3 ratios with `{rounded.xl}` corners.

## Components

### Top Navigation

**`top-nav`** - White nav bar pinned to the top of every page. 64px tall, `{colors.canvas}` background. Carries the brand wordmark + logo at left, a primary horizontal menu (Product, Solutions, Resources, Pricing, Enterprise) center, right-side cluster with "Sign in" text-link, "Sign up free" `{component.button-primary}`, and a sometimes-visible language selector. Menu items in `{typography.nav-link}` (Inter 14px / 500).

**`nav-pill-group`** - A small pill-radius wrapper around 2-3 sub-nav segments (e.g. a product-mode switcher between "Personal" / "Teams" / "Enterprise"). Background `{colors.surface-soft}` with internal padding 6px, rounded `{rounded.pill}`. Active segment renders as a white-canvas pill with a subtle drop shadow inside the wrapper. The pill-in-pill treatment is one of the baseline's signature interactive components.

### Buttons

**`button-primary`** - The signature primary CTA. Background `{colors.primary}` (#0a0a0a), text `{colors.on-primary}`, type `{typography.button}` (Inter 14px / 600), padding 12px × 20px, height 40px, rounded `{rounded.md}` (8px). Active state `button-primary-active` shifts to `{colors.primary-active}` (#242424). On dark surfaces the primary inverts to white background with `{colors.surface-dark}` text; hover shifts to `{colors.emphasis-hover-dark}`.

**`button-secondary`** - White button with hairline outline. Background `{colors.canvas}`, text `{colors.ink}`, 1px hairline border, same padding + height + radius as primary.

**`button-icon-circular`** - 36 × 36px circular icon button. Background `{colors.canvas}`, hairline border, ink-color icon. Used for share, "view more", carousel arrows.

**`button-text-link`** - Inline text button, no background. Used for "Sign in" in the top nav and inline CTA links inside cards.

**`text-link`** - Inline body links in `{colors.ink}` (the brand keeps inline links monochrome). Underlined on hover (not documented per the no-hover policy, but mentioned for context).

### Cards & Containers

**`hero-band`** - White-canvas hero with a 7-5 grid: h1 + sub-headline + button row on the left, `{component.hero-app-mockup-card}` on the right. Vertical padding `{spacing.section}` (96px).

**`hero-app-mockup-card`** - A larger product-UI mockup card showing an actual app fragment (e.g. a scheduling widget with calendar grid, time slots, and a primary "Confirm" button inside). Background `{colors.canvas}`, 1px hairline border, rounded `{rounded.xl}` (16px), subtle drop shadow. Used as the hero's right-side artifact.

**`feature-card`** - Used in 3-up feature grids ("With us, appointment scheduling is easy"). Background `{colors.surface-card}` (#f5f5f5), rounded `{rounded.lg}` (12px), internal padding `{spacing.xl}` (32px). Carries a small icon at top, an `{typography.title-md}` headline, and a body description in `{typography.body-md}`.

**`feature-icon-card`** - A simpler card variant used in 4-up feature grids on lower-density bands. Background `{colors.canvas}` with hairline border, rounded `{rounded.lg}`, padding `{spacing.lg}` (24px). Carries a small icon, `{typography.title-sm}` title, short description.

**`product-mockup-card`** - A card showing actual product UI fragments (workflow editor, calendar grid, integration grid, automation flow). Background `{colors.canvas}`, rounded `{rounded.lg}`, padding `{spacing.lg}` (24px). The product UI inside has its own internal chrome - these cards display the product, they don't decorate around it.

**`testimonial-card`** - Used in customer-quote grids. Background `{colors.surface-card}`, rounded `{rounded.lg}`, padding `{spacing.lg}` (24px). Top row carries a `{component.avatar-circle}` + name + role; below sits the testimonial quote in `{typography.body-md}`.

**`pricing-tier-card`** - Standard tier card. Background `{colors.canvas}`, rounded `{rounded.lg}`, padding `{spacing.xl}` (32px). Carries the plan name in `{typography.title-lg}`, price in `{typography.display-sm}`, feature checklist in `{typography.body-md}`, and a `{component.button-primary}` at the bottom.

**`pricing-tier-card-featured`** - The featured tier (typically "Teams"). Background flips to `{colors.surface-dark}` (#032e3a = Petrol-900), text inverts to `{colors.on-dark}`. The dark surface IS the featured-tier signal - no accent border, no badge, no scale shift.

### Inputs & Forms

**`text-input`** - Standard text input. Background `{colors.canvas}`, text `{colors.ink}`, type `{typography.body-md}`, rounded `{rounded.md}` (8px), padding 10px × 14px, height 40px. 1px hairline border in `{colors.hairline}`.

**`text-input-focused`** - Focus state. Border thickens or shifts to `{colors.ink}` for emphasis.

### Feedback

**`toast`** - Transient notification surfaced in response to a user action (saved, copied, error). Background `{colors.canvas}`, 1px hairline border, rounded `{rounded.md}` (8px), padding 12px × 16px, subtle drop shadow (`0 4px 12px rgba(0,0,0,0.08)`). Carries a leading 16px status icon, a single-line message in `{typography.body-sm}` (`{colors.ink}`), and an optional inline close button (`{component.button-icon-circular}` at 24px). Width caps at 420px; on mobile it stretches to viewport minus 16px gutters.

Variants flag status via the icon color and a thin 3px left border:
- **`toast-success`** - Icon and left border in `{colors.success}` (#10b981).
- **`toast-warning`** - Icon and left border in `{colors.warning}` (#f59e0b).
- **`toast-danger`** - Icon and left border in `{colors.danger}` (#c0392b).
- **`toast-neutral`** - No left border, icon in `{colors.ink-mute}`. The default for non-status confirmations ("Link copied").

**Stack behavior:** Toasts stack bottom-right on desktop (anchored `{spacing.lg}` from the viewport edges), bottom-center on mobile. Newest toast appears at the bottom of the stack and pushes older ones up. Maximum 3 visible at once; further toasts queue and surface as earlier ones dismiss.

**Auto-dismiss:** Default 4s for `toast-success` and `toast-neutral`, 6s for `toast-warning`, **never auto-dismiss** for `toast-danger` (errors require user acknowledgement). Hovering a toast pauses its dismiss timer; the timer resumes on hover-out. Toasts with action buttons (e.g. "Undo") are sticky until clicked or explicitly dismissed.

**Don't:** stack toasts more than 3 deep, use toasts for content that needs to be read carefully (use a modal or inline alert instead), or fire toasts on page load (they're a response to action, not a greeting).

### Tags / Badges

**`badge-pill`** - Small pill label used for category tags ("Product", "Article", "New"). Background `{colors.surface-card}` (default) or `{colors.petrol-200}` for brand-emphasis pills, text `{colors.ink}`, type `{typography.caption}` (13px / 500), rounded `{rounded.pill}`, padding 4px × 12px.

**`eyebrow`** - Small uppercase label above a headline. Type `{typography.eyebrow}` (12px / 500 / uppercase / letter-spacing 0.1em), color `{colors.petrol-600}`. The single place Petrol appears in running editorial type - signature brand cue.

**`avatar-circle`** - 36px diameter, rounded `{rounded.full}`. Either holds a photo or a `{colors.surface-card}` fill with initials in `{typography.caption}`.

**`rating-stars`** - Inline star rating in `{colors.warning}` (#f59e0b). Used near testimonial avatars to display a 5-star satisfaction score.

### Tab / Filter

**`category-tab`** + **`category-tab-active`** - Used inside the nav-pill-group. Inactive: transparent background, `{colors.ink-mute}` text. Active: `{colors.canvas}` background, `{colors.ink}` text, subtle drop shadow inside the pill-group wrapper. Padding 8px × 14px, rounded `{rounded.md}`.

### CTA / Footer

**`cta-band-light`** - A pre-footer "Smarter, simpler scheduling" CTA card. Background `{colors.surface-card}`, rounded `{rounded.lg}`, padding `{spacing.xxl}` (48px). Carries an h2 in `{typography.display-sm}`, a sub-line, and a `{component.button-primary}` centered.

**`footer`** - Deep petrol footer that closes every page. Background `{colors.surface-dark}` (#032e3a = Petrol-900), text `{colors.on-dark-soft}`. 4-column link list at desktop covering Product / Solutions / Company / Resources. Vertical padding 64px. The wordmark sits at the top-left in `{colors.on-dark}`. On a light-only site the footer is the only dark surface - the deliberate inversion visually closes the page.

## Do's and Don'ts

### Do
- Reserve `{colors.primary}` (#0a0a0a = ink) for primary CTAs and h1/h2 type. The button is near-black, not Petrol.
- Use Display for every display headline. Pair with Inter body. Never blur the boundary.
- Apply negative letter-spacing on display sizes (-0.5 to -2px). Display without it reads as off-brand.
- Use `{component.feature-card}` (light gray) and `{component.product-mockup-card}` (white with chrome) deliberately - the gray cards signal "abstract feature claim", white cards signal "look at the actual product".
- Embed real product UI fragments inside marketing cards. Don't paint marketing illustrations of the product when you can show the product itself.
- Keep avatar circles at 36px, perfect circles, with `{colors.surface-card}` as default fill.
- Use `{component.nav-pill-group}` for grouped sub-nav segments. The pill-in-pill treatment is signature.
- End every page with the dark footer. The light-to-dark transition is part of the editorial rhythm.

### Don't
- Don't use Petrol on primary CTAs. The action layer is **black**; Petrol lives at the accent layer (links, focus rings, eyebrows, dark surfaces).
- Don't introduce a second accent palette (yellow, pink, lavender). Petrol is the only chromatic voice. Semantic colors (`success`, `warning`, `danger`) are exceptions and only appear in their semantic role.
- Don't bold display weight beyond 600. Display at 700 reads as bombastic.
- Don't use rounded radius beyond `{rounded.xl}` (16px) on cards. Larger radii read as consumer-app, not professional booking software.
- Don't put dark surface cards anywhere except the footer and the featured pricing tier. The dark surface is a deliberate, scarce signal.
- Don't repeat the same surface mode in two consecutive bands. The pacing alternates white → petrol-tint card → white → product-mockup-card → white → dark-footer.
- Don't add hover state styling beyond what the system already encodes - primary darkens on press; nothing else changes.

## Responsive Behavior

### Breakpoints

| Name | Width | Key Changes |
|---|---|---|
| Mobile | < 768px | Hamburger nav; hero h1 64→32px; hero-app-mockup-card stacks below content; feature grids 1-up; pricing 1-up; footer 4 cols → 1 |
| Tablet | 768-1024px | Top nav stays horizontal but tightens; nav-pill-group wraps; feature cards 2-up; pricing 2-up |
| Desktop | 1024-1440px | Full top-nav with all menu items; 3-up feature cards; 4-up pricing tiers |
| Wide | > 1440px | Same as desktop with more outer breathing room; max content width caps at 1200px |

### Touch Targets
- `{component.button-primary}` at minimum 40 × 40px.
- `{component.button-icon-circular}` at exactly 36 × 36 - slightly under WCAG's 44 × 44 but the centered icon and full-circle silhouette compensate.
- `{component.text-input}` height is 40px.
- `{component.category-tab}` rendered inside nav-pill-group has 8 × 14 padding; effective tap area meets 44px+ with the surrounding pill.

### Collapsing Strategy
- Top nav collapses to hamburger at < 768px; menu opens as a full-screen sheet.
- Hero band's 7-5 grid collapses to single-column on mobile - h1 + sub-head + buttons first, then the app-mockup card below.
- Feature grids reduce columns rather than scaling cards down.
- Pricing tier cards collapse 4 → 2 → 1; featured-tier dark surface stays visually distinct at every breakpoint.
- Nav-pill-group wraps to multi-row on tablet if the segments don't fit horizontally.
- Avatar + testimonial card layouts stay grid-aligned at every breakpoint.

### Image Behavior
- Product UI fragments inside cards retain native aspect ratios; the cards themselves resize.
- Avatar photos crop to circles at every breakpoint.
- Hero app-mockup card scales proportionally on mobile - the calendar grid stays legible.

## Iteration Guide

1. Focus on ONE component at a time. Reference its YAML key directly (`{component.feature-card}`, `{component.pricing-tier-card-featured}`).
2. Variants of an existing component (`-active`, `-disabled`, `-focused`) live as separate entries in `components:`.
3. Use `{token.refs}` everywhere - never inline hex.
4. Never document hover. Default and Active/Pressed states only.
5. Display headlines stay Display 600 with negative letter-spacing. Body stays Inter 400. The trinity does not blur.
6. The dark footer is the only dark surface on most pages. Don't add other dark cards casually.
7. When in doubt about emphasis: bigger Display before bolder Display.

## Known Gaps

- The Display face is intentionally generic. The baseline uses Inter weight 600 with -0.04em tracking; projects with a licensed custom display face should swap it in and preserve the weight + tracking signature.
- The Petrol palette covers 7 stops (50/100/200/400/600/800/900). Mid-stops 300/500/700 are intentionally not defined - if a project needs them, derive by interpolation and document in the project's `DESIGN.md`, but the baseline reads cleaner without them.
- The dark theme is documented as a complete inversion (canvas, surface, text), but most consuming projects use only the dark footer + featured-tier surface. Wiring a full dark mode is opt-in via the activation strategy (system-preference + `data-theme` override) in `Theme Activation`.
- Hairline tokens use rgba notation (`rgb(0 0 0 / 0.10)`) rather than hex (`#e5e7eb`). Both are valid - rgba composites cleanly on Petrol-tinted surfaces, hex is more grep-friendly. Pick one per project, document the choice.
- Animation and transition timings (calendar slot picker, schedule confirmation, integration grid hover-reveal) are not in scope.
- Form validation states beyond `{component.text-input-focused}` are not extracted - error / success states would need a sign-up or booking flow to confirm.
- The actual product surface (e.g. a booking widget under `app.example.com/{user}`) is the product itself, not a marketing surface; its spec is out of scope.
- Avatar photos in testimonial sections sometimes carry pastel circular fills with initials instead of photographs; both treatments coexist on the same page.
