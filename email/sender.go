package email

import (
	"fmt"
	"net/smtp"
)

/*
SendEmail is a helper function that uses the SMTP protocol to send a message.
It handles the authentication and message formatting.
*/
func SendEmail(host, port, fromEmail, password, toEmail, subject, body string) error {
	/* Set up authentication information. */
	auth := smtp.PlainAuth("", fromEmail, password, host)

	/* SMTP server address */
	address := host + ":" + port

	/* Message headers and body
	We use \r\n because SMTP protocol expects CRLF line endings */
	msg := []byte("To: " + toEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
		"\r\n" +
		body + "\r\n")

	/* Send the email */
	err := smtp.SendMail(address, auth, fromEmail, []string{toEmail}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email via SMTP: %w", err)
	}

	return nil
}
