import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime, timedelta

from analyze import VulnerabilityAnalyzer
from charts import PDFReportGenerator
from dotenv import load_dotenv
from database import VulnerabilityDB

load_dotenv()


class EmailAlertSystem:
    """
    Système d'alertes par email basé sur les abonnés stockés en base.
    """

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.sender_email = os.getenv("SENDER_EMAIL", "")
        self.sender_password = os.getenv("SENDER_PASSWORD", "")
        # On ne lit plus RECIPIENT_EMAILS ici, on utilise la BDD
        self.db = VulnerabilityDB()

        if not self.sender_email or not self.sender_password:
            print("Configuration email incomplète. Vérifiez les variables d'environnement.")

    def _get_recipient_emails(self, frequency: str | None = None):
        """
        Récupère les emails des abonnés actifs depuis la base.
        """
        subscribers = self.db.get_active_subscribers(frequency=frequency)
        return [s["email"] for s in subscribers]

    def send_alert_email(self, subject: str, message: str, attachment_path: str | None = None,
                         frequency: str | None = None) -> bool:
        """
        Envoie un email d'alerte à tous les abonnés actifs (optionnellement filtrés par fréquence).
        """
        if not self.sender_email or not self.sender_password:
            print("Configuration email manquante, envoi annulé.")
            return False

        recipient_emails = self._get_recipient_emails(frequency=frequency)
        if not recipient_emails:
            print("Aucun abonné actif trouvé, envoi annulé.")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(recipient_emails)
            msg["Subject"] = f"Veille DevSecOps - {subject}"

            body = (
                "Bonjour,\n\n"
                f"{message}\n\n"
                "Cordialement,\n"
                "Système de Veille DevSecOps CICD\n"
                f"Généré automatiquement le {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )
            msg.attach(MIMEText(body, "plain"))

            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename={os.path.basename(attachment_path)}",
                )
                msg.attach(part)

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            text = msg.as_string()
            server.sendmail(self.sender_email, recipient_emails, text)
            server.quit()
            print(f"Email envoyé à {recipient_emails} destinataires.")
            return True
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'email : {str(e)}")
            return False

    def check_and_send_critical_alerts(self) -> bool:
        """
        Vérifie les vulnérabilités critiques récentes et envoie une alerte 'immédiate'.
        """
        recent_critical = VulnerabilityAnalyzer.get_critical_vulnerabilities()
        if not recent_critical:
            print("Aucune vulnérabilité critique récente détectée.")
            return False

        subject = f"Nouvelles Vulnérabilités Critiques ({len(recent_critical)})"
        message_lines = [
            "ALERTES DE SÉCURITÉ CRITIQUES",
            f"{len(recent_critical)} nouvelles vulnérabilités critiques ont été détectées :",
            "",
        ]

        for vuln in recent_critical[:10]:  # Limiter à 10 pour éviter les emails trop longs
            message_lines.append(
                f"- CVE: {vuln.get('cve_id') or 'N/A'} | "
                f"Date: {vuln.get('published_date').strftime('%d/%m/%Y') if vuln.get('published_date') else 'N/A'} | "
                f"Score CVSS: {vuln.get('cvss_score') or 'N/A'}\n"
                f"  Titre: {vuln.get('title') or 'N/A'}\n"
                f"  Lien: {vuln.get('url') or 'N/A'}"
            )

        if len(recent_critical) > 10:
            message_lines.append(
                f"\n… et {len(recent_critical) - 10} autres vulnérabilités critiques."
            )

        message_lines.append(
            "\nActions recommandées :\n"
            "- Évaluer l'impact sur vos systèmes\n"
            "- Appliquer les correctifs disponibles\n"
            "- Surveiller les communications de sécurité\n"
            "- Mettre à jour vos dépendances\n"
            "- Consulter l'interface web pour plus de détails."
        )

        message = "\n".join(message_lines)
        return self.send_alert_email(subject, message, frequency="immediate")

    def send_weekly_report(self) -> bool:
        """
        Envoie un rapport hebdomadaire (PDF en pièce jointe) aux abonnés 'weekly'.
        """
        pdf_generator = PDFReportGenerator()
        pdf_filename = f"rapport_hebdomadaire_{datetime.now().strftime('%Y%m%d')}.pdf"
        pdf_path = pdf_generator.generate_report(pdf_filename)

        subject = f"Rapport Hebdomadaire de Veille DevSecOps - {datetime.now().strftime('%d/%m/%Y')}"

        weekly_trends = VulnerabilityAnalyzer.analyze_trends_with_pandas(days=7)
        stats = VulnerabilityAnalyzer.get_statistics()

        message_lines = [
            "RAPPORT HEBDOMADAIRE DE VEILLE DEVSECOPS",
            "",
            "Résumé de la semaine écoulée :",
            "",
            "Statistiques globales :",
            f"- Total des vulnérabilités : {stats.get('total_vulnerabilities', 0)}",
            f"- Vulnérabilités critiques : {stats.get('critical', 0)}",
            f"- Vulnérabilités haute sévérité : {stats.get('high', 0)}",
            "",
        ]

        if weekly_trends.get("monthly_trends"):
            recent_period = max(weekly_trends["monthly_trends"].keys())
            weekly_count = weekly_trends["monthly_trends"][recent_period]
            message_lines.append(f"Nouvelles vulnérabilités cette semaine : {weekly_count}")

        if weekly_trends.get("top_components"):
            top_comp = list(weekly_trends["top_components"].keys())[:3]
            message_lines.append(
                "Composants les plus affectés : " + ", ".join(top_comp)
            )

        message_lines.append(
            "\nLe rapport PDF détaillé est joint à cet email.\n"
            "Consultez l'interface web pour des analyses plus poussées."
        )

        message = "\n".join(message_lines)

        success = self.send_alert_email(
            subject, message, attachment_path=pdf_path, frequency="weekly"
        )

        if os.path.exists(pdf_path):
            os.remove(pdf_path)

        return success

    def send_custom_alert(self, title: str, content: str, include_pdf: bool = False) -> bool:
        """
        Envoie une alerte personnalisée à tous les abonnés actifs.
        """
        attachment_path = None
        if include_pdf:
            pdf_generator = PDFReportGenerator()
            attachment_path = pdf_generator.generate_report("rapport_custom.pdf")

        message = f"ALERTE PERSONNALISÉE : {title}\n\n{content}"
        success = self.send_alert_email(title, message, attachment_path=attachment_path)

        if attachment_path and os.path.exists(attachment_path):
            os.remove(attachment_path)

        return success
    
    def send_periodic_reports_for_all_subscribers(self) -> bool:
        """
        Envoie un rapport PDF à tous les abonnés 'periodic' en respectant leur period_days.
        Chaque abonné reçoit un rapport couvrant sa propre période (2 à 30 jours).
        """
        # Récupérer les abonnés périodiques
        subscribers = self.db.get_active_subscribers(frequency="periodic")
        if not subscribers:
            print("Aucun abonné périodique trouvé.")
            return False

        any_success = False

        for sub in subscribers:
            email = sub["email"]
            period_days = sub.get("period_days") or 7
            try:
                period_days = int(period_days)
            except (TypeError, ValueError):
                period_days = 7
            period_days = max(2, min(period_days, 30))

            print(f"Envoi du rapport sur {period_days} jours à {email}...")

            # Générer les tendances/statistiques pour cette période
            trends = VulnerabilityAnalyzer.analyze_trends_with_pandas(days=period_days)
            stats = VulnerabilityAnalyzer.get_statistics()

            # Générer un rapport PDF (tu peux adapter generate_report pour accepter days si besoin)
            pdf_generator = PDFReportGenerator()
            pdf_filename = f"rapport_veille_{period_days}j_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = pdf_generator.generate_report(pdf_filename)

            subject = f"Rapport de veille DevSecOps - {period_days} derniers jours"
            message_lines = [
                "RAPPORT DE VEILLE DEVSECOPS",
                "",
                f"Période analysée : {period_days} derniers jours.",
                "",
                "Statistiques globales (base complète) :",
                f"- Total des vulnérabilités : {stats.get('total_vulnerabilities', 0)}",
                f"- Vulnérabilités critiques : {stats.get('critical', 0)}",
                f"- Vulnérabilités haute sévérité : {stats.get('high', 0)}",
                "",
            ]

            if trends.get("monthly_trends"):
                last_period = max(trends["monthly_trends"].keys())
                count = trends["monthly_trends"][last_period]
                message_lines.append(f"Nouvelles vulnérabilités sur la période : {count}")

            if trends.get("top_components"):
                top_comp = list(trends["top_components"].keys())[:3]
                if top_comp:
                    message_lines.append(
                        "Composants les plus affectés : " + ", ".join(top_comp)
                    )

            message_lines.append(
                "\nLe rapport PDF détaillé est joint à cet email.\n"
                "Consultez également le tableau de bord web pour plus de détails."
            )
            message = "\n".join(message_lines)

            # Envoi à ce seul abonné
            # On bypass _get_recipient_emails pour cibler une adresse précise
            original_get_recipients = self._get_recipient_emails
            try:
                def _single_recipient(_freq=None):
                    return [email]
                self._get_recipient_emails = _single_recipient

                success = self.send_alert_email(
                    subject, message, attachment_path=pdf_path, frequency=None
                )
                if success:
                    any_success = True
            finally:
                self._get_recipient_emails = original_get_recipients

            if os.path.exists(pdf_path):
                os.remove(pdf_path)

        return any_success

