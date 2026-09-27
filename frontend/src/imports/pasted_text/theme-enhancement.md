CRITICAL UI ENHANCEMENT — ADD LIGHT / DARK / SYSTEM THEME

The existing PRAHARI AI application is working correctly.

DO NOT change any investigation logic, functionality, data flow, API
integration, analysis pipeline, report generation, or existing features.

ONLY add a professional theme system.

==================================================
THEME OPTIONS
==================================================

Add exactly three theme options:

☀ Light
🌙 Dark
🖥 System

The user should be able to switch between them from the application
settings / profile menu.

==================================================
LIGHT THEME
==================================================

Keep the existing PRAHARI AI light interface as the default.

Use the existing:

• White/light backgrounds
• Existing card styling
• Existing borders
• Existing typography
• Existing branding
• Existing status colors

Do NOT redesign the current light theme.

==================================================
DARK THEME
==================================================

Create a professional cybersecurity/SOC-style dark theme.

Use:

• Dark background
• Dark cards/panels
• High-contrast text
• Subtle borders
• Existing PRAHARI AI accent colors
• Existing risk/status colors

Maintain excellent readability.

Do NOT use excessive gradients, neon effects, glowing elements,
or gaming-style visuals.

The dark theme should feel like a professional SOC / forensic
investigation platform.

==================================================
SYSTEM THEME
==================================================

When "System" is selected:

Automatically follow the user's operating-system preference.

If the OS is in light mode:
→ PRAHARI uses Light.

If the OS is in dark mode:
→ PRAHARI uses Dark.

Use the browser/system prefers-color-scheme setting.

==================================================
THEME SWITCHER
==================================================

Create a compact theme selector:

Theme
○ Light
○ Dark
● System

or an equivalent clean dropdown/menu.

The selected option must be visually obvious.

==================================================
PERSISTENCE
==================================================

Remember the user's selected theme.

If the user selects:

Dark

and refreshes the page:

→ remain Dark.

If the user selects:

Light

and refreshes:

→ remain Light.

If the user selects:

System:

→ automatically follow OS preference.

Use localStorage or the existing application preference mechanism.

==================================================
NO FLASH
==================================================

Prevent a white/light flash when opening the application in Dark mode.

The correct theme should be applied as early as possible during
page initialization.

==================================================
ALL PAGES
==================================================

The theme must apply consistently across the entire PRAHARI AI system:

• Dashboard
• Investigations
• Upload Email
• Investigation Overview
• Risk Score
• IOC Analysis
• Threat Intelligence
• Authentication
• Geo / Network
• Evidence Graph
• MITRE ATT&CK
• Timeline
• Reports
• Settings
• Modals
• Dropdowns
• Tables
• Forms
• Alerts
• Loading states
• Empty states

==================================================
DATA VISUALIZATION
==================================================

Ensure charts, graphs and visualizations remain readable in both
Light and Dark themes.

Do NOT change the underlying data.

Evidence Graph:

• Nodes remain visible
• Connections remain visible
• Labels remain readable
• Zoom/pan remains functional

Risk Score:

• Maintain existing risk semantics
• Maintain existing severity indicators

==================================================
FORENSIC REPORT
==================================================

IMPORTANT:

Do NOT change the existing forensic report/PDF generation logic.

The theme should NOT accidentally alter forensic evidence,
investigation data or report contents.

If the report is intentionally generated independently from the
application theme, keep the existing report appearance unchanged.

==================================================
ACCESSIBILITY
==================================================

Ensure:

✓ Text has sufficient contrast
✓ Buttons remain readable
✓ Inputs remain readable
✓ Links remain distinguishable
✓ Focus states remain visible
✓ Status indicators do not rely only on color
✓ Dark mode is comfortable for long investigations

==================================================
MOBILE
==================================================

The theme selector must also work on mobile.

Do NOT introduce horizontal scrolling.

Keep the existing mobile-responsive layout unchanged.

==================================================
DESKTOP REGRESSION
==================================================

The current desktop Light theme must look essentially the same
as it does now.

Do NOT redesign the existing UI.

==================================================
ACCEPTANCE TEST
==================================================

Test:

1. Select Light
   → entire application becomes Light.

2. Select Dark
   → entire application becomes Dark.

3. Select System
   → follows OS/browser preference.

4. Refresh page
   → selected preference remains.

5. Navigate between pages
   → theme remains consistent.

6. Open modals/dropdowns
   → theme remains consistent.

7. Open Evidence Graph
   → remains readable.

8. Open Geo / Network
   → remains readable.

9. Open Report
   → remains readable.

10. Switch Light ↔ Dark repeatedly
    → no broken components or layout shifts.

FINAL RULE:

THIS IS A THEME/UI ENHANCEMENT ONLY.

DO NOT MODIFY THE PRAHARI AI INVESTIGATION PIPELINE.

DO NOT MODIFY REAL EMAIL ANALYSIS.

DO NOT MODIFY DEMO INVESTIGATION.

DO NOT MODIFY GEOIP OR THREAT INTELLIGENCE.

DO NOT MODIFY RISK SCORING.

DO NOT MODIFY PDF GENERATION.

PRESERVE THE EXISTING PRAHARI AI DESIGN AND FUNCTIONALITY.
ONLY ADD A POLISHED LIGHT / DARK / SYSTEM THEME SYSTEM.