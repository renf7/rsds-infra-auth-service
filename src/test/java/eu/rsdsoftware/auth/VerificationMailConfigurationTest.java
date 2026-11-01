package eu.rsdsoftware.auth;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class VerificationMailConfigurationTest {
    @Test void mailAdapterSendsOnlyToTheValidatedRecipient() {
        var sender=mock(JavaMailSender.class);
        var mail=new VerificationMailConfiguration().verificationMail(sender,new MockEnvironment().withProperty("rsds.auth.mail-from","auth@example.test"));
        mail.send("alice@example.test","123456");
        var capture=ArgumentCaptor.forClass(SimpleMailMessage.class); verify(sender).send(capture.capture());
        assertArrayEquals(new String[]{"alice@example.test"},capture.getValue().getTo());
        assertEquals("auth@example.test",capture.getValue().getFrom());
        assertTrue(java.util.Objects.requireNonNull(capture.getValue().getText()).contains("123456"));
    }
}
