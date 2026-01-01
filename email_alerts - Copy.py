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

# Charger les variables d'environnement
load_dotenv()

class EmailAlertSystem:
    """Système d'alertes par email"""

    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.sender_email = os.getenv('SENDER_EMAIL', '')
        self.sender_password = os.getenv('SENDER_PASSWORD', '')
        self.recipient_emails = os.getenv('RECIPIENT_EMAILS', '').split(',')

        # Vérifier la configuration
        if not self.sender_email or not self.sender_password:
            print("⚠️ Configuration email incomplète. Vérifiez les variables d'environnement.")

    def send_alert_email(self, subject, message, attachment_path=None):
        """Envoyer un email d'alerte"""
        if not self.sender_email or not self.sender_password:
            print("❌ Configuration email manquante")
            return False

        try:
            # Créer le message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipient_emails)
            msg['Subject'] = f"🚨 Veille DevSecOps - {subject}"

            # Corps du message
            body = f"""
Bonjour,

{message}

Cordialement,
Système de Veille DevSecOps & CI/CD
Généré automatiquement le {datetime.now().strftime('%d/%m/%Y à %H:%M')}
            """
            msg.attach(MIMEText(body, 'plain'))

            # Ajouter une pièce jointe si fournie
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(attachment_path)}")
                    msg.attach(part)

            # Envoyer l'email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            text = msg.as_string()
            server.sendmail(self.sender_email, self.recipient_emails, text)
            server.quit()

            print(f"✅ Email envoyé à {len(self.recipient_emails)} destinataire(s)")
            return True

        except Exception as e:
            print(f"❌ Erreur lors de l'envoi de l'email: {str(e)}")
            return False

    def check_and_send_critical_alerts(self):
        """Vérifier et envoyer des alertes pour les vulnérabilités critiques"""
        # Récupérer les vulnérabilités critiques des dernières 24h
        recent_critical = VulnerabilityAnalyzer.get_critical_vulnerabilities()

        if not recent_critical:
            print("ℹ️ Aucune vulnérabilité critique récente détectée")
            return False

        subject = f"Nouvelles Vulnérabilités Critiques ({len(recent_critical)} détectées)"

        message = f"""
🚨 ALERTES DE SÉCURITÉ CRITIQUES 🚨

{len(recent_critical)} nouvelle(s) vulnérabilité(s) critique(s) ont été détectées :

"""

        for vuln in recent_critical[:10]:  # Limiter à 10 pour éviter les emails trop longs
            message += f"""
🔴 CVE: {vuln['cve_id']}
📅 Date: {vuln['published_date'].strftime('%d/%m/%Y') if vuln['published_date'] else 'N/A'}
🎯 Score CVSS: {vuln['cvss_score']}
📝 Titre: {vuln['title']}
🔗 Lien: {vuln['url']}

"""

        if len(recent_critical) > 10:
            message += f"\n... et {len(recent_critical) - 10} autre(s) vulnérabilité(s) critique(s)."

        message += """

🔧 Actions recommandées :
• Évaluer l'impact sur vos systèmes
• Appliquer les correctifs disponibles
• Surveiller les communications de sécurité
• Mettre à jour vos dépendances

Consultez l'interface web pour plus de détails.
        """

        return self.send_alert_email(subject, message)

    def send_weekly_report(self):
        """Envoyer un rapport hebdomadaire"""
        # Générer le rapport PDF
        pdf_generator = PDFReportGenerator()
        pdf_filename = f"rapport_hebdomadaire_{datetime.now().strftime('%Y%m%d')}.pdf"
        pdf_path = pdf_generator.generate_report(pdf_filename)

        subject = f"Rapport Hebdomadaire de Veille DevSecOps - {datetime.now().strftime('%d/%m/%Y')}"

        # Statistiques de la semaine
        weekly_trends = VulnerabilityAnalyzer.analyze_trends_with_pandas(days=7)
        stats = VulnerabilityAnalyzer.get_statistics()

        message = f"""
📊 RAPPORT HEBDOMADAIRE DE VEILLE DEVSECOPS 📊

Résumé de la semaine écoulée :

📈 Statistiques globales :
• Total des vulnérabilités: {stats.get('total_vulnerabilities', 0)}
• Vulnérabilités critiques: {stats.get('critical', 0)}
• Vulnérabilités haute sévérité: {stats.get('high', 0)}

📅 Tendances de la semaine :
"""

        if weekly_trends.get('monthly_trends'):
            # Les tendances sont stockées par périodes mensuelles, on prend la plus récente
            recent_period = max(weekly_trends['monthly_trends'].keys())
            weekly_count = weekly_trends['monthly_trends'][recent_period]
            message += f"• Nouvelles vulnérabilités cette semaine: {weekly_count}\n"

        if weekly_trends.get('top_components'):
            top_comp = list(weekly_trends['top_components'].keys())[:3]
            message += f"• Composants les plus affectés: {', '.join(top_comp)}\n"

        message += """

Le rapport PDF détaillé est joint à cet email.

Consultez l'interface web pour des analyses plus poussées.
        """

        success = self.send_alert_email(subject, message, pdf_path)

        # Nettoyer le fichier PDF temporaire
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

        return success

    def send_custom_alert(self, title, content, include_pdf=False):
        """Envoyer une alerte personnalisée"""
        message = f"""
🔔 ALERTE PERSONNALISÉE

{title}

{content}
        """

        attachment_path = None
        if include_pdf:
            pdf_generator = PDFReportGenerator()
            attachment_path = pdf_generator.generate_report("rapport_custom.pdf")

        success = self.send_alert_email(title, message, attachment_path)

        # Nettoyer le fichier PDF si créé
        if attachment_path and os.path.exists(attachment_path):
            os.remove(attachment_path)

        return success
