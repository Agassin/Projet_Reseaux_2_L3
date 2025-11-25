import java.util.HashSet;
import java.util.Set;

public class SecurityContext {
    private int sequenceNumber = 0;
    private Set<String> seenMessages = new HashSet<>();
    private final long MAX_AGE = 300000; // 5 minutes en millisecondes

    public String addSecurityHeaders(String message) {
        long timestamp = System.currentTimeMillis();
        sequenceNumber++;

        String securedMessage = timestamp + "|" + sequenceNumber + "|" + message;

        // Protection contre le replay (sans synchronized, peut être imprécis)
        if (seenMessages.contains(securedMessage)) {
            throw new SecurityException("Message rejoué détecté");
        }
        seenMessages.add(securedMessage);

        // Nettoyage périodique
        if (seenMessages.size() > 1000) {
            seenMessages.clear();
        }

        return securedMessage;
    }

    public String verifySecurityHeaders(String securedMessage) {
        String[] parts = securedMessage.split("\\|", 3);
        if (parts.length != 3) {
            throw new SecurityException("En-têtes de sécurité manquantes");
        }

        long timestamp = Long.parseLong(parts[0]);
        int seq = Integer.parseInt(parts[1]);
        String message = parts[2];

        // Vérification timestamp
        long currentTime = System.currentTimeMillis();
        if (Math.abs(currentTime - timestamp) > MAX_AGE) {
            throw new SecurityException("Message trop ancien (tolérance de 5 minutes dépassée)");
        }

        // Vérification séquence
        if (seq <= sequenceNumber) {
            throw new SecurityException("Numéro de séquence invalide (plus petit ou égal au dernier vu)");
        }
        sequenceNumber = seq;

        return message;
    }
}