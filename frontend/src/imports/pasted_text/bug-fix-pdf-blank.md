CRITICAL BUG FIX — FORENSIC PDF IS BLANK

DO NOT CHANGE THE PRAHARI AI INVESTIGATION PROCESS.

The investigation UI and report content are already working correctly.
The ONLY problem is that when I click "Generate PDF" / "Export PDF",
the downloaded PDF opens as a BLANK WHITE PAGE.

==================================================
CURRENT BEHAVIOR — WRONG
==================================================

Investigation works correctly in the application.

The Report page displays the forensic report correctly.

But after clicking:

Generate PDF / Export PDF

the resulting PDF opens with:

BLANK WHITE PAGE

No report content is visible.

==================================================
REQUIRED BEHAVIOR
==================================================

The exported PDF must contain the SAME forensic report that is
currently visible on the Report page.

Report page:
        ↓
Generate PDF
        ↓
Standalone PDF
        ↓
Same visible report content

==================================================
DO NOT MODIFY
==================================================

DO NOT change:

• Email investigation
• EML parsing
• IOC extraction
• Threat intelligence
• GeoIP
• ASN / ISP
• Authentication
• Risk scoring
• Evidence correlation
• Neo4j
• MITRE ATT&CK
• Timeline
• Investigation state
• Demo investigation
• Real email investigation
• Report content
• Report UI design

Everything above is already working.

ONLY FIX THE PDF EXPORT.

==================================================
PDF MUST INCLUDE
==================================================

• PRAHARI AI branding
• Case ID
• Investigation date
• Email summary
• Sender / recipient / subject
• Risk score
• Verdict
• IOC analysis
• Threat intelligence
• Authentication results
• Geo / Network Context
• Evidence correlation
• MITRE ATT&CK
• Forensic timeline
• Findings
• Evidence/source information

All information must come from the CURRENT investigation.

If the current investigation is a real uploaded email,
export that real investigation.

If the current investigation is the demo,
export the demo investigation.

NEVER substitute demo data.

==================================================
IMPORTANT — PDF RENDERING
==================================================

The PDF must be generated from the actual report data/template,
NOT from an empty iframe, blank browser container, or unloaded
prototype canvas.

Make sure the PDF generation waits until the report content
has been fully rendered before capturing/exporting it.

If the current implementation uses browser screenshot/canvas
capture, ensure all report elements are rendered before export.

If necessary, use a proper HTML-to-PDF/document generation
approach so the content is actually embedded into the PDF.

The exported PDF must contain REAL selectable/rendered content,
not just a blank page.

==================================================
PAGE HANDLING
==================================================

If the report is longer than one page:

Automatically create multiple PDF pages.

Do NOT crop the report.

Do NOT create blank pages.

Do NOT lose tables, text, graphs or evidence sections.

==================================================
FIGMA WATERMARK
==================================================

Also ensure that the generated standalone PRAHARI AI PDF does NOT
contain any Figma Make/editor URL or Figma watermark.

Remove ONLY the Figma-generated watermark.

DO NOT remove legitimate URLs that are part of the forensic evidence.

==================================================
FOOTER
==================================================

Use:

PRAHARI AI — Forensic Intelligence Report

No Figma URL.

==================================================
REAL INVESTIGATION TEST
==================================================

Upload a real .EML.

Complete the existing investigation.

Open:

Report

Verify the report is visible.

Then click:

Generate PDF

Open the generated PDF.

The PDF must show the SAME report content.

==================================================
DEMO TEST
==================================================

Open the existing Demo Investigation.

Open:

Report

Generate PDF.

The PDF must contain the existing demo report.

==================================================
FINAL ACCEPTANCE TEST
==================================================

✓ Report page displays correctly
✓ Generate PDF works
✓ PDF is NOT blank
✓ PDF contains actual report content
✓ Current investigation data is preserved
✓ Real investigation exports real data
✓ Demo exports demo data
✓ Multiple pages work correctly
✓ Tables are visible
✓ Text is visible
✓ Risk score is visible
✓ IOC data is visible
✓ Geo/Network data is visible
✓ MITRE ATT&CK is visible
✓ Timeline is visible
✓ No Figma watermark
✓ No Figma URL
✓ No investigation logic has been changed

IMPORTANT:

THIS IS A PDF EXPORT BUG ONLY.

MAKE THE SMALLEST POSSIBLE CODE CHANGE.

DO NOT REBUILD OR MODIFY THE PRAHARI AI INVESTIGATION SYSTEM.