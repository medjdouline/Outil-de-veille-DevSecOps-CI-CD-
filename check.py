from email_alerts import EmailAlertSystem

if __name__ == "__main__":
    system = EmailAlertSystem()
    ok = system.send_custom_alert(
        title="Test alerte DevSecOps",
        content="Ceci est un email de test envoyé depuis le projet de veille DevSecOps.",
        include_pdf=False,
    )
    print("Envoi réussi ?", ok)
