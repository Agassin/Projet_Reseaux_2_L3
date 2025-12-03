package Application;

import java.util.HashSet;
import java.util.Set;

public class SecurityContextFX {
    // Séparer les compteurs d'envoi et de réception
    private int sendSequenceNumber = 0;
    private int receiveSequenceNumber = 0;

    private Set<String> seenMessages = new HashSet<>();
    private final long MAX_AGE = 300000; // 5 minutes

    public String addSecurityHeaders(String message) {
        long timestamp = System.currentTimeMillis();
        sendSequenceNumber++;

        String securedMessage = timestamp + "|" + sendSequenceNumber + "|" + message;

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

        // Vérification séquence (maintenant sur receiveSequenceNumber)
        if (seq <= receiveSequenceNumber) {
            throw new SecurityException("Numéro de séquence invalide (plus petit ou égal au dernier vu)");
        }
        receiveSequenceNumber = seq;

        // Protection anti-replay basique
        if (seenMessages.contains(securedMessage)) {
            throw new SecurityException("Message rejoué détecté");
        }
        seenMessages.add(securedMessage);

        // Nettoyage périodique
        if (seenMessages.size() > 1000) {
            seenMessages.clear();
        }

        return message;
    }
}