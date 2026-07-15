import csv
import io


def rows_to_csv(rows, fieldnames):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row[name] if name in row.keys() else "" for name in fieldnames})
    return output.getvalue()


def rows_to_pdf(title, rows, fieldnames, summary_lines=None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        summary_text = "\n".join(summary_lines or [])
        text = title + ("\n\n" + summary_text if summary_text else "") + "\n\n" + rows_to_csv(rows, fieldnames)
        return text.encode("utf-8")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Spacer(1, 8)]
    for line in summary_lines or []:
        story.append(Paragraph(line, styles["BodyText"]))
    if summary_lines:
        story.append(Spacer(1, 10))

    data = [fieldnames]
    for row in rows[:500]:
        data.append([str(row[name] if name in row.keys() else "")[:80] for name in fieldnames])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer.read()
