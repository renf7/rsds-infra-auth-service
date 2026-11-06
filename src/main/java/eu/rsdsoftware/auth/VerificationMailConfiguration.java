package eu.rsdsoftware.auth;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
@Configuration
public class VerificationMailConfiguration {
    @Bean VerificationMail verificationMail(JavaMailSender sender,Environment environment) {
        String from=environment.getProperty("rsds.auth.mail-from","no-reply@rsdsoftware.eu");
        return (email,code)->{
            var message=new SimpleMailMessage(); message.setFrom(from); message.setTo(email);
            message.setSubject("RSDS account verification");
            message.setText("Your RSDS verification code is: "+code+"\nIt expires in 10 minutes. If you did not request this, ignore this email.");
            sender.send(message);
        };
    }
}
