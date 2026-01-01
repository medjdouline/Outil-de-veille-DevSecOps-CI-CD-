import os
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # mode headless

from flask import Flask, render_template, request, jsonify, send_file

from config import DevelopmentConfig
from database import VulnerabilityDB
from analyze import VulnerabilityAnalyzer
from charts import PDFReportGenerator

try:
    from automation import automation_system, start_automation_on_startup
    automation_available = True
except ImportError:
    automation_available = False
    print("Module automation non disponible.")

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

# Base de donnees
db = VulnerabilityDB()

# Demarrer l'automatisation au demarrage si disponible
if automation_available:
    start_automation_on_startup()


@app.route("/")
def index():
    """Page d'accueil."""
    stats = VulnerabilityAnalyzer.get_statistics()
    trends = VulnerabilityAnalyzer.get_top_affected_components(limit=5)
    return render_template("index.html", stats=stats, trends=trends)


@app.route("/search", methods=["GET", "POST"])
def search():
    """Page de recherche."""
    results = []
    if request.method == "POST":
        severity = request.form.get("severity") or None
        component = request.form.get("component") or None
        days = request.form.get("days") or None
        days = int(days) if days else None

        results = VulnerabilityAnalyzer.filter_vulnerabilities(
            severity=severity,
            component=component,
            days=days,
        )

    return render_template("search.html", results=results)


@app.route("/reports")
def reports():
    """Page des rapports."""
    stats = VulnerabilityAnalyzer.get_statistics()
    severity_breakdown = VulnerabilityAnalyzer.get_severity_distribution()
    trends = VulnerabilityAnalyzer.get_trends(days=30)
    charts = VulnerabilityAnalyzer.generate_matplotlib_charts(days=30)
    text_analysis = VulnerabilityAnalyzer.get_text_vectorization()
    summaries = VulnerabilityAnalyzer.generate_descriptions_summary()

    return render_template(
        "reports.html",
        stats=stats,
        severity_breakdown=severity_breakdown,
        trends=trends,
        charts=charts,
        text_analysis=text_analysis,
        summaries=summaries,
    )


@app.route("/admin")
def admin():
    """Page d'administration."""
    return render_template("admin.html")


@app.route("/alerts")
def alerts():
    """Page d'inscription aux alertes."""
    return render_template("alerts.html")


@app.route("/add-test-data")
def add_test_data_route():
    """Ajouter des donnees de test via l'interface web."""
    from add_test_data import add_test_data

    try:
        add_test_data()
        return jsonify({"status": "success", "message": "Donnees de test ajoutees."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/vulnerabilities", methods=["GET"])
def api_vulnerabilities():
    """API pour recuperer les vulnerabilites au format JSON (avec pagination)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)

    df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe()
    total = len(df)

    start = (page - 1) * per_page
    end = start + per_page
    paginated_df = df.iloc[start:end]

    vulnerabilities = []
    for _, row in paginated_df.iterrows():
        vulnerabilities.append(
            {
                "id": int(row.name) if hasattr(row, "name") else 0,
                "cve_id": row["cve_id"],
                "title": row["title"],
                "severity": row["severity"],
                "cvss_score": row["cvss_score"],
                "component": row["affected_component"],
                "url": row["url"],
            }
        )

    data = {
        "total": total,
        "pages": (total + per_page - 1) // per_page,
        "current_page": page,
        "vulnerabilities": vulnerabilities,
    }
    return jsonify(data)


@app.route("/api/statistics", methods=["GET"])
def api_statistics():
    """API pour les statistiques globales."""
    return jsonify(VulnerabilityAnalyzer.get_statistics())


@app.route("/api/subscribe-alerts", methods=["POST"])
def subscribe_alerts():
    """
    API pour s'inscrire aux alertes.

    JSON attendu :
    {
      "email": "...",
      "frequency": "immediate" ou "periodic",
      "period_days": 7  # optionnel, utilise si frequency = "periodic"
    }
    """
    from email_alerts import EmailAlertSystem  # import local pour eviter les boucles

    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    frequency = (data.get("frequency") or "immediate").strip().lower()
    period_days = data.get("period_days")

    if not email:
        return jsonify({"status": "error", "message": "Email manquant."}), 400

    if frequency not in ("immediate", "periodic"):
        frequency = "immediate"

    try:
        # Enregistrer l'abonnement dans la base
        if frequency == "periodic":
            try:
                period_days = int(period_days)
            except (TypeError, ValueError):
                period_days = 7
            period_days = max(2, min(period_days, 30))
        else:
            period_days = None

        db.add_subscriber(email=email, frequency=frequency, period_days=period_days)

        # Si immediate: envoyer tout de suite un rapport PDF a cet email
        if frequency == "immediate":
            system = EmailAlertSystem()

            period = 7  # nombre de jours couverts par le rapport immediat
            pdf_generator = PDFReportGenerator()
            pdf_filename = (
                f"rapport_immediat_{period}j_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            pdf_path = pdf_generator.generate_report(pdf_filename)

            stats = VulnerabilityAnalyzer.get_statistics()
            message_lines = [
                "ALERTE IMMEDIATE - Rapport de veille DevSecOps",
                "",
                f"Periode analysee : {period} derniers jours.",
                "",
                "Statistiques globales :",
                f"- Total des vulnerabilites : {stats.get('total_vulnerabilities', 0)}",
                f"- Vulnerabilites critiques : {stats.get('critical', 0)}",
                f"- Vulnerabilites haute severite : {stats.get('high', 0)}",
                "",
                "Le rapport PDF detaille est joint a cet email.",
            ]
            message = "\n".join(message_lines)

            # Envoyer uniquement a cet email
            original_get_recipients = system._get_recipient_emails

            try:
                # Accepte n'importe quels arguments pour rester compatible
                def _single_recipient(*args, **kwargs):
                    return [email]

                system._get_recipient_emails = _single_recipient

                system.send_alert_email(
                    subject="Rapport immediat DevSecOps",
                    message=message,
                    attachment_path=pdf_path,
                    frequency=None,
                )
            finally:
                system._get_recipient_emails = original_get_recipients

            if os.path.exists(pdf_path):
                os.remove(pdf_path)

            msg = f"Abonnement immediat cree et rapport envoye a {email}."
        else:
            msg = (
                f"Abonnement periodique cree pour {email}. "
                f"Rapports tous les {period_days} jours."
            )

        return jsonify({"status": "success", "message": msg})
    except Exception as e:
        print("Erreur /api/subscribe-alerts:", repr(e))
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/generate-pdf")
def generate_pdf():
    """Generer et telecharger un rapport PDF."""
    try:
        pdf_generator = PDFReportGenerator()
        filename = pdf_generator.generate_report()
        return send_file(
            filename,
            as_attachment=True,
            download_name=f"rapport_veille_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype="application/pdf",
        )
    except Exception as e:
        return f"Erreur lors de la generation du PDF : {str(e)}", 500


@app.route("/automation/start")
def start_automation():
    """Demarrer l'automatisation."""
    if not automation_available:
        return (
            jsonify({"status": "error", "message": "Module automation non disponible."}),
            500,
        )

    try:
        automation_system.start_automation()
        return jsonify({"status": "success", "message": "Automatisation demarree."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/automation/stop")
def stop_automation():
    """Arreter l'automatisation."""
    if not automation_available:
        return (
            jsonify({"status": "error", "message": "Module automation non disponible."}),
            500,
        )

    try:
        automation_system.stop_automation()
        return jsonify({"status": "success", "message": "Automatisation arretee."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/automation/status")
def automation_status():
    """Statut de l'automatisation."""
    if not automation_available:
        return jsonify(
            {
                "is_running": False,
                "next_runs": [],
                "error": "Module automation non disponible.",
            }
        )

    import schedule

    return jsonify(
        {
            "is_running": automation_system.is_running,
            "next_runs": [
                {"job": str(job), "next_run": str(job.next_run)} for job in schedule.jobs
            ],
        }
    )


@app.route("/automation/run-collectors")
def run_collectors():
    """Executer manuellement les collecteurs."""
    if not automation_available:
        return (
            jsonify({"status": "error", "message": "Module automation non disponible."}),
            500,
        )

    try:
        automation_system.run_manual_collection()
        return jsonify(
            {"status": "success", "message": "Collecteurs executes manuellement."}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/automation/test-alerts")
def test_alerts():
    """Tester les alertes email."""
    if not automation_available:
        return (
            jsonify({"status": "error", "message": "Module automation non disponible."}),
            500,
        )

    try:
        automation_system.run_manual_alerts()
        return jsonify({"status": "success", "message": "Test des alertes envoye."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/automation/test-periodic")
def test_periodic_reports():
    """Tester l'envoi des rapports periodiques (PDF)."""
    if not automation_available:
        return (
            jsonify({"status": "error", "message": "Module automation non disponible."}),
            500,
        )

    try:
        stats = automation_system.send_weekly_report()
        return jsonify({"status": "success", "details": stats})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.errorhandler(404)
def not_found_error(_):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
