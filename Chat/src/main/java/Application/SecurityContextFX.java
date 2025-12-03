package Application;

import java.util.HashSet;
import java.util.Set;

public class SecurityContextFX {
    private int sequenceNumber = 0;
    private final Set<String> seenMessages = new HashSet<>();
    private final long MAX_AGE = 300000; // 5 minutes en millisecondes

    // ⭐ SYNCHRONISÉ pour la sécurité des threads
    public synchronized String addSecurityHeaders(String message) {
        long timestamp = System.currentTimeMillis();
        sequenceNumber++;

        String securedMessage = timestamp + "|" + sequenceNumber + "|" + message;

        if (seenMessages.contains(securedMessage)) {
            throw new SecurityException("Message rejoué détecté");
        }
        seenMessages.add(securedMessage);

        if (seenMessages.size() > 1000) {
            seenMessages.clear();
        }
        return securedMessage;
    }

    // ⭐ SYNCHRONISÉ pour la sécurité des threads
    public synchronized String verifySecurityHeaders(String securedMessage) {
        String[] parts = securedMessage.split("\\|", 3);
        if (parts.length != 3) {
            throw new SecurityException("En-têtes de sécurité manquantes");
        }

        long timestamp = Long.parseLong(parts[0]);
        int seq = Integer.parseInt(parts[1]);
        String message = parts[2];

        long currentTime = System.currentTimeMillis();
        if (Math.abs(currentTime - timestamp) > MAX_AGE) {
            throw new SecurityException("Message trop ancien");
        }

        if (seq <= sequenceNumber) {
            throw new SecurityException("Numéro de séquence invalide");
        }
        sequenceNumber = seq;
        seenMessages.add(securedMessage);

        return message;
    }
}