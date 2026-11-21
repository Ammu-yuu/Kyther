# Kyther — Launch Video Plan

> Promo/launch video script for Kyther, the plugin-based OSINT orchestration engine.
> Two cuts: **16:9** (LinkedIn/site/GitHub) and **9:16** (Reels/Shorts/TikTok).
> Palette: ground `#0f0d13`, accent `#c9b3ec`. Fonts: Quicksand (brand) + JetBrains Mono (terminal).

**Concept:** *One name in. Everything the internet knows, out.* Open on a single search →
fan out into a confidence-scored dossier → widen to the whole console → land the clever beat
(it audits its own security) → lock on the wings logo.

**Tone:** sleek, terminal-cinematic. **Music:** dark minimal synth / hacker-ambient, ~90–100 BPM,
one build into the risk-score reveal, resolve on the logo.

---

## Cut A — 16:9 (~22s)

| # | Time | Visual (b-roll) | On-screen text | Narration (VO) | Sound |
|---|------|-----------------|----------------|----------------|-------|
| 1 | 0:00–0:03 | Black → blinking cursor in Home terminal; a username typed live; wings logo faint behind | `> search --username` | "Give it a single name…" | keystrokes, low synth swell |
| 2 | 0:03–0:07 | `running scan_` streams; result lines populate fast — verified accounts, emails, breaches | `19 sources · one dossier` | "…and Kyther pulls together what the public internet already knows about it." | rapid data-ticks |
| 3 | 0:07–0:11 | Fused identity card + risk tile flips to `High · 74/100`; timeline/graph glimpse | `scored · auto-pivoted` | "Accounts, breaches, infrastructure — scored, and pivoted automatically." | rising tone, soft impact on score |
| 4 | 0:11–0:15 | Quick cuts: Threat Actors gallery → Cyber Attacks feed → World Pulse's 3 region columns | `threat intel · world pulse` | "Live threat actors, ransomware feeds, and how the world's framing any topic." | montage whooshes |
| 5 | 0:15–0:19 | The `⛊ Audit` run in-terminal resolving to green `0 high — clean` | `⛊ audit --self` | "It even audits its own security." | single confident synth stab |
| 6 | 0:19–0:22 | Wings logo center on `#0f0d13`; tagline; Kyther as a PWA on a phone beside it | `Kyther · github.com/Ammu-yuu/Kyther` | "Kyther. Open-source intelligence, orchestrated." | logo-lock hit, tail reverb |

---

## Cut B — 9:16 vertical (~24s)

Re-timed for silent autoplay and a phone-first frame: **bigger burned-in captions in the upper
third**, one clear subject per shot (vertical has no room for side-by-side), and the phone PWA
shot promoted because it's literally the native frame. Slightly longer holds so fast cuts don't
feel frantic on mobile.

| # | Time | Visual (stack vertically, subject centered) | On-screen text (upper third, large) | Narration (VO) | Sound |
|---|------|----------------------------------------------|-------------------------------------|----------------|-------|
| 1 | 0:00–0:04 | Full-bleed terminal, thumb types a username; wings logo watermark top | `one name.` | "Give it a single name…" | keystrokes, synth swell |
| 2 | 0:04–0:08 | Vertical scan stream fills the frame top→bottom (accounts, emails, breaches) | `19 sources → 1 dossier` | "…and Kyther pulls together what the public internet already knows." | rapid data-ticks |
| 3 | 0:08–0:13 | Identity card centered; risk tile punches in to `High · 74/100`; hold | `scored automatically` | "Accounts, breaches, infrastructure — scored, and pivoted for you." | build → impact on score |
| 4 | 0:13–0:18 | Three quick full-frame cards: Threat Actor dossier → Ransomware victim → World Pulse column | `threat intel · world pulse` | "Live threat actors, ransomware feeds, and how the world's framing any topic." | montage whooshes |
| 5 | 0:18–0:21 | `⛊ Audit` terminal resolves to green `0 high — clean`, centered | `it audits itself` | "It even audits its own security." | confident synth stab |
| 6 | 0:21–0:24 | **Phone in-hand**, Kyther PWA open, then wings logo fills frame | `Kyther` / `github.com/Ammu-yuu/Kyther` | "Kyther. Open-source intelligence, orchestrated." | logo-lock hit, reverb tail |

**Vertical safe-zones:** keep text out of the top ~10% and bottom ~15% (platform UI). Center subjects.

---

## Narration — clean read (~48 words, works for both cuts)

> "Give it a single name… and Kyther pulls together what the public internet already knows about
> it. Accounts, breaches, infrastructure — scored, and pivoted automatically. Live threat actors,
> ransomware feeds, and how the world's framing any topic. It even audits its own security.
> **Kyther — open-source intelligence, orchestrated.**"

*No-voice version:* drop the VO, let captions + music carry, add one extra beat of logo hold.

---

## Sound design

- **Music:** dark minimal synth, steady pulse, single build into beat 3, resolve on logo.
- **SFX:** mechanical keystrokes (1) · data-tick blips (2) · soft "lock" on the risk score (3) ·
  montage whooshes (4) · single stab on the clean-audit reveal (5) · logo impact + reverb tail (6).
- **Captions:** burn in all on-screen text — accessibility + silent autoplay.

---

## Capture checklist (record locally first — this is the b-roll)

1. **Home:** type a username in Quick Search → Search; record the streaming scan + dossier + risk tile.
   *Use a demo/consented target — never a real person's private data.*
2. **Threat Actors:** slow scroll across the dossier-card gallery.
3. **Cyber Attacks:** the recent-victims list populating.
4. **World Pulse:** run a neutral topic; capture the US/UK/India columns.
5. **Audit:** click `⛊ Audit`; capture the terminal resolving to the green summary.
6. **Logo/PWA:** wings logo on dark; Kyther installed on a phone home screen.

Record at 2×/retina, hide any real personal data, grab a few extra seconds per clip for trim room.
For the 9:16 cut, either record the browser at a narrow width or capture the PWA on an actual phone.

---

## Share copy

**LinkedIn caption**
> I built Kyther — a plugin-based OSINT engine that takes one identifier and orchestrates ~19 public
> sources into a single, confidence-scored dossier: accounts, breaches, infrastructure, risk. It
> carries live threat-actor and ransomware feeds, a "World Pulse" discourse explorer, PDF reports,
> and installs on your phone as a PWA. It even runs a security self-audit on its own code.
>
> 15 seconds of what it does 👇
>
> #OSINT #CyberSecurity #Python #BuildInPublic #ThreatIntel

**Short / X**
> One name in → a scored OSINT dossier out. 19 sources, auto-pivoted, live threat feeds, and it
> audits its own security. Meet Kyther 👇 #OSINT #infosec

---

## If rendering with the `brag` skill

```
/brag --tone sleek --duration 22 --title "Kyther" --voice     # 16:9, narrated
/brag --tone sleek --format vertical --duration 24 --title "Kyther"   # 9:16, music-only
```
Drop `--voice` for a music-only cut. Point it at the repo — do not feed it `.env`, real scan
results, or the `~/.kyther` caches.
