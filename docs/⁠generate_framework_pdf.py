from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable

def generate_pdf(filename="DUBAI_TECH_Resilient_Architecture_Framework_V0.1.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54, leftMargin=54,
        topMargin=54, bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    primary_color = colors.HexColor("#0B2545")    # Deep Navy
    secondary_color = colors.HexColor("#134074")  # Slate Blue
    body_color = colors.HexColor("#1D2D44")       # Dark Charcoal
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=14,
        textColor=secondary_color,
        spaceAfter=18
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=primary_color,
        spaceBefore=12,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=body_color,
        spaceAfter=6
    )
    
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=15,
        spaceAfter=4
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("DUBAI.TECH Resilient Architecture Framework — V0.1", title_style))
    story.append(Paragraph("<b>Author / Architect:</b> Waleed Mubarak &nbsp;|&nbsp; <b>Target:</b> Core Architecture Alignment", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=primary_color, spaceAfter=12))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary & Core Philosophy", heading_style))
    exec_text = (
        "In hyper-connected and large-scale AI ecosystems, traditional perimeter defense and software-only "
        "trust models are fundamentally insufficient. DUBAI.TECH requires a paradigm shift toward <b>Cyber-Physical Sovereignty</b> "
        "and <b>Resilience-by-Design</b>.<br/>"
        "When trust dissolves or components fail, systems must not degrade gracefully into vulnerable states; "
        "they must fail closed, irreversibly, and securely."
    )
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 6))

    # 2. Foundational Principles
    story.append(Paragraph("2. Foundational Architecture Principles", heading_style))
    story.append(Paragraph("The framework is built upon five immutable foundational pillars:", body_style))
    
    pillars = [
        "<b>Threat Model Alignment:</b> Anticipating adversarial state-mutations at both software boundaries and hardware-software interfaces.",
        "<b>Layered Resilience:</b> Ensuring that failure in one zone (e.g., external AI agents or third-party cloud services) is strictly isolated and cannot propagate to the core sovereign infrastructure.",
        "<b>Cryptographic & Structural Boundaries:</b> Enforcing hard cryptographic immutability and memory-level guarantees (such as bare-metal zeroization) to prevent unauthorized persistence.",
        "<b>State-Machine Invariants:</b> Governing system operations through mathematically rigid state transitions that reject ambiguous or mutable runtimes.",
        "<b>Fail-Closed Enforcement:</b> Mandating that any loss of integrity, authorization failure, or anomaly triggers immediate, irreversible method invalidation and state locking."
    ]
    for p in pillars:
        story.append(Paragraph(f"• {p}", bullet_style))
    story.append(Spacer(1, 6))

    # 3. Core Layers
    story.append(Paragraph("3. Core Architectural Layers (From Metal to Cloud)", heading_style))
    layers = [
        "<b>Layer 0: Hardware Root of Trust (Silicon-Level):</b> Cryptographic immutability and secure boot protocols anchoring trust directly to hardware.",
        "<b>Layer 1: Fail-Closed Core & State Machines:</b> Governing operational transitions with strict invariants and automated stub-replacement upon security triggers.",
        "<b>Layer 2: Bare-Memory Scrubbing & Zeroization:</b> Eliminating volatile RAM persistence instantly upon threat detection or emergency shutdown.",
        "<b>Layer 3: Sovereign Cloud Fabric & High-Density Compute:</b> Encrypted, resilient data processing and infrastructure designed to remain operational and sovereign under hostile network conditions."
    ]
    for l in layers:
        story.append(Paragraph(f"• {l}", bullet_style))
    story.append(Spacer(1, 6))

    # 4. Next Steps
    story.append(Paragraph("4. Next Steps for V0.1", heading_style))
    steps = [
        "<b>Architectural Review:</b> Aligning key stakeholders on these invariant principles.",
        "<b>Component Mapping:</b> Defining the precise integration points between AI agents, compute nodes, and sovereign data storage.",
        "<b>Implementation Blueprint:</b> Translating these framework principles into verifiable code-enforced policies."
    ]
    for s in steps:
        story.append(Paragraph(f"• {s}", bullet_style))

    doc.build(story)
    print(f"Successfully generated: {filename}")

if __name__ == "__main__":
    generate_pdf()
