package Security;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SecurityContext {
    // ⭐ SÉPARATION DES COMPTEURS
    private int sendSequenceNumber = 0;
    private int receiveSequenceNumber = 0;

    private Set<String> seenMessages = Collections.synchronizedSet(new HashSet<>());
    private final long MAX_AGE = 300000; // 5 minutes

    public synchronized String addSecurityHeaders(String message) {
        long timestamp = System.currentTimeMillis();
        sendSequenceNumber++; // ⭐ Compteur d'ENVOI uniquement

        String securedMessage = timestamp + "|" + sendSequenceNumber + "|" + message;
        return securedMessage;
    }

    public synchronized String verifySecurityHeaders(String securedMessage) {
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
            throw new SecurityException("Message trop ancien (> 5 minutes)");
        }

        // ⭐ Vérification avec le compteur de RÉCEPTION
        if (seq <= receiveSequenceNumber) {
            throw new SecurityException("Numéro de séquence invalide: " + seq
                    + " (attendu > " + receiveSequenceNumber + ")");
        }
        receiveSequenceNumber = seq; // ⭐ Mise à jour du compteur de réception

        // Protection anti-replay
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