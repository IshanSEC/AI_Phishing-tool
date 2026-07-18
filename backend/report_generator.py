import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class PDFReportGenerator:
    def __init__(self):
        # Create reports directory if it doesn't exist
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def _generate_gauge_chart(self, risk_score, scan_id):
        """Generates a threat gauge horizontal bar chart using Matplotlib and saves it to a temp file."""
        plt.figure(figsize=(6, 1.2))
        
        # Color bar logic
        if risk_score >= 75:
            color = "#EF4444" # Red
            label = "High Risk"
        elif risk_score >= 30:
            color = "#F59E0B" # Yellow/Orange
            label = "Medium Risk"
        else:
            color = "#10B981" # Green
            label = "Low Risk"
            
        # Draw background bar (0-100 scale)
        plt.barh([0], [100], color="#E5E7EB", height=0.4, label="Safe Range")
        # Draw risk bar
        plt.barh([0], [risk_score], color=color, height=0.4)
        
        # Threshold markers
        plt.axvline(30, color="#6B7280", linestyle="--", alpha=0.5)
        plt.axvline(75, color="#6B7280", linestyle="--", alpha=0.5)
        
        # Labels and formatting
        plt.xlim(0, 100)
        plt.ylim(-0.4, 0.4)
        plt.title(f"Threat Score: {risk_score}/100 ({label})", fontsize=10, fontweight="bold", color="#1F2937")
        
        # Hide ticks and spines
        ax = plt.gca()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['left'].set_visible(False)
        ax.get_yaxis().set_visible(False)
        
        plt.xticks([0, 30, 75, 100], ['0 (Low)', '30 (Medium)', '75 (High)', '100'], fontsize=8, color="#4B5563")
        plt.tight_layout()
        
        temp_chart_path = os.path.join(self.reports_dir, f"temp_chart_{scan_id}.png")
        plt.savefig(temp_chart_path, dpi=150, transparent=True)
        plt.close()
        return temp_chart_path

    def generate_report(self, scan_data):
        """Compiles a professional ReportLab PDF document for a given scan payload."""
        scan_id = scan_data["id"]
        scan_type = scan_data["type"]
        risk_score = scan_data["risk_score"]
        prediction = scan_data["prediction"]
        created_at = scan_data.get("created_at", datetime.utcnow().isoformat())
        
        # Parse datetime
        try:
            dt = datetime.fromisoformat(created_at.replace("Z", ""))
            formatted_date = dt.strftime("%B %d, %Y - %H:%M:%S UTC")
        except Exception:
            formatted_date = created_at
            
        pdf_path = os.path.join(self.reports_dir, f"threat_report_{scan_id}.pdf")
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        
        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        style_header = ParagraphStyle(
            name='HeaderStyle',
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#FFFFFF'),
            spaceAfter=6
        )
        style_title = ParagraphStyle(
            name='TitleStyle',
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=colors.HexColor('#1E293B'),
            spaceAfter=12,
            spaceBefore=12
        )
        style_section = ParagraphStyle(
            name='SectionStyle',
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=6,
            spaceBefore=14
        )
        style_body = ParagraphStyle(
            name='BodyStyle',
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#334155'),
            leading=12
        )
        style_bold = ParagraphStyle(
            name='BoldStyle',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#1E293B'),
            leading=12
        )
        style_alert = ParagraphStyle(
            name='AlertStyle',
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#EF4444') if risk_score >= 75 else colors.HexColor('#F59E0B') if risk_score >= 30 else colors.HexColor('#10B981'),
            spaceAfter=8
        )
        
        story = []
        
        # 1. Header Banner Table (Corporate Logo Placeholder + Title)
        header_data = [
            [
                Paragraph("<b>ThreatShield-AI Threat Index</b>", style_header),
                Paragraph("<font color='#00BFFF'><b>[ SHIELD SECURE ]</b></font>", ParagraphStyle(
                    name='LogoSub', fontName='Helvetica-Bold', fontSize=12, alignment=2, textColor=colors.HexColor('#FFFFFF')
                ))
            ]
        ]
        header_table = Table(header_data, colWidths=[5.5*inch, 2.0*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#050816')),
            ('PADDING', (0,0), (-1,-1), 12),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 15))
        
        # 2. Summary details table
        details = []
        if scan_type == "email":
            details = [
                [Paragraph("<b>Scan Type:</b>", style_bold), Paragraph("Email Threat Analysis", style_body)],
                [Paragraph("<b>Subject:</b>", style_bold), Paragraph(scan_data["details"].get("subject", "N/A"), style_body)],
                [Paragraph("<b>Sender:</b>", style_bold), Paragraph(f"{scan_data['details'].get('sender_name', 'N/A')} &lt;{scan_data['details'].get('sender_email', 'N/A')}&gt;", style_body)],
                [Paragraph("<b>SPF / DKIM:</b>", style_bold), Paragraph(f"SPF Pass: {scan_data['details'].get('spf_pass', 'N/A')} | DKIM Pass: {scan_data['details'].get('dkim_pass', 'N/A')}", style_body)]
            ]
        else:  # File scan
            file_meta = scan_data["details"].get("metadata", {})
            details = [
                [Paragraph("<b>Scan Type:</b>", style_bold), Paragraph("Static File Malware Analysis", style_body)],
                [Paragraph("<b>Filename:</b>", style_bold), Paragraph(file_meta.get("file_name", "N/A"), style_body)],
                [Paragraph("<b>File Size:</b>", style_bold), Paragraph(f"{file_meta.get('file_size', 0):,} bytes", style_body)],
                [Paragraph("<b>MD5 Hash:</b>", style_bold), Paragraph(file_meta.get("md5", "N/A"), style_body)],
                [Paragraph("<b>SHA-256 Hash:</b>", style_bold), Paragraph(file_meta.get("sha256", "N/A"), style_body)]
            ]
            
        summary_left_data = [
            [Paragraph("<b>SCAN METADATA SUMMARY</b>", style_title)],
            [Paragraph(f"<b>Scan Log ID:</b> {scan_id}", style_body)],
            [Paragraph(f"<b>Timestamp:</b> {formatted_date}", style_body)],
            [Spacer(1, 8)]
        ] + [[Table(details, colWidths=[1.5*inch, 3.8*inch])]]
        
        # Convert table to flowable layout
        summary_table = Table(details, colWidths=[1.3*inch, 4.0*inch])
        summary_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        
        # Compile chart
        temp_chart = self._generate_gauge_chart(risk_score, scan_id)
        chart_flowable = Image(temp_chart, width=2.8*inch, height=0.6*inch)
        
        # Table of Summary + Verdict and Chart Side-by-Side
        verdict_color = '#EF4444' if risk_score >= 75 else '#F59E0B' if risk_score >= 30 else '#10B981'
        verdict_html = f"Verdict: <font color='{verdict_color}'><b>{prediction.upper()}</b></font>"
        
        right_panel_data = [
            [Paragraph(verdict_html, style_alert)],
            [chart_flowable],
            [Spacer(1, 8)],
            [Paragraph("<b>Threat Level:</b> " + ("High Risk" if risk_score >= 75 else "Medium Risk" if risk_score >= 30 else "Low Risk / Safe"), style_bold)],
            [Paragraph("Confidence Rating: " + str(scan_data.get("confidence", 100)) + "%", style_body)]
        ]
        right_panel_table = Table(right_panel_data)
        right_panel_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('PADDING', (0,0), (-1,-1), 10),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ]))
        
        # Major layout block
        layout_data = [
            [
                Table([
                    [Paragraph("<b>METADATA SUMMARY</b>", style_section)],
                    [summary_table]
                ], colWidths=[4.3*inch]),
                right_panel_table
            ]
        ]
        layout_table = Table(layout_data, colWidths=[4.5*inch, 3.0*inch])
        layout_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(layout_table)
        story.append(Spacer(1, 15))
        
        # 3. Explainable AI Threat Indicators
        story.append(Paragraph("EXPLAINABLE AI (XAI) THREAT INDICATORS", style_section))
        
        indicators = scan_data["details"].get("xai_indicators", [])
        
        if not indicators:
            story.append(Paragraph("No suspicious features or malware signature indicators were extracted. The content matches standard safety parameters.", style_body))
        else:
            table_rows = [
                [
                    Paragraph("<b>Threat Indicator</b>", style_bold),
                    Paragraph("<b>Severity</b>", style_bold),
                    Paragraph("<b>Trigger Matches</b>", style_bold),
                    Paragraph("<b>Technical Explanation</b>", style_bold)
                ]
            ]
            for ind in indicators:
                matches_str = ", ".join(ind.get("matches", [])) if isinstance(ind.get("matches"), list) else str(ind.get("matches", "N/A"))
                if not matches_str:
                    matches_str = ind.get("details", "N/A")
                
                sev = ind.get("severity", "Low")
                sev_color = '#EF4444' if sev == "High" else '#F59E0B' if sev == "Medium" else '#10B981'
                
                table_rows.append([
                    Paragraph(ind.get("category") or ind.get("indicator") or "Threat Indicator", style_bold),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", style_body),
                    Paragraph(matches_str, style_body),
                    Paragraph(ind.get("description") or ind.get("explanation") or "N/A", style_body)
                ])
                
            ind_table = Table(table_rows, colWidths=[1.8*inch, 0.8*inch, 2.0*inch, 2.9*inch])
            ind_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(ind_table)
            
        story.append(Spacer(1, 15))
        
        # 4. Mitigation Recommendations
        story.append(Paragraph("RECOMMENDED MITIGATION PROCEDURES", style_section))
        
        recs = []
        if risk_score >= 75:
            if scan_type == "email":
                recs = [
                    "<b>DO NOT click any links</b> or enter password credentials on pages connected to this email.",
                    "<b>Flag and report</b> this communication to your Security Operations Center (SOC) immediately.",
                    "<b>Blacklist</b> the sender domain and reply-to addresses on enterprise network routers and filters."
                ]
            else:
                recs = [
                    "<b>DO NOT execute or run</b> this file. Quarantine and isolate the host machine if run accidentally.",
                    "<b>Purge</b> the threat from storage drives and run a deep cybersecurity antivirus scanner.",
                    "<b>Alert security administration</b> to verify if other client terminals received similar payloads."
                ]
        elif risk_score >= 30:
            recs = [
                "<b>Exercise caution.</b> Treat URLs and attachments in this transaction with standard cybersecurity scrutiny.",
                "Verify the identity of the sender via out-of-band communication (phone call, face-to-face confirmation) before replying.",
                "Configure email SPF/DKIM verification profiles to reduce spoofing attempts from similar domains."
            ]
        else:
            recs = [
                "This file/email is evaluated as low-risk. Standard operations may proceed safely.",
                "Ensure local endpoint antivirus protections are updated and running routinely.",
                "Regular security training remains recommended for all users across departments."
            ]
            
        bullet_list = []
        for rec in recs:
            bullet_list.append([Paragraph("&bull;", style_bold), Paragraph(rec, style_body)])
            
        rec_table = Table(bullet_list, colWidths=[0.2*inch, 7.3*inch])
        rec_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(rec_table)
        
        # Footer note
        story.append(Spacer(1, 20))
        story.append(Paragraph("<font color='#64748B'><i>Notice: ThreatShield-AI Static Scanner uses automated rules and machine learning. No guarantee of absolute security accuracy is implied. Handled under SOC internal standards.</i></font>", ParagraphStyle(name='FooterText', fontName='Helvetica-Oblique', fontSize=7, alignment=1)))
        
        # Build Document
        doc.build(story)
        
        # Clean up chart file
        if os.path.exists(temp_chart):
            try:
                os.remove(temp_chart)
            except Exception:
                pass
                
        return pdf_path
