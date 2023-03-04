package com.antonzhdanov.apache.sshd.agent.cloud;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Base64;

import static java.util.Objects.requireNonNull;
import static org.testcontainers.shaded.org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil.encodePublicKey;
import static org.testcontainers.shaded.org.bouncycastle.crypto.util.PublicKeyFactory.createKey;

public class OpenSshServerContainer extends GenericContainer<OpenSshServerContainer> {
    public OpenSshServerContainer(PublicKey publicKey) {
        super("lscr.io/linuxserver/openssh-server:latest");

        withEnv("PUID", "1000");
        withEnv("PGID", "1000");
        withEnv("PUBLIC_KEY", encode(requireNonNull(publicKey)));
        withEnv("SUDO_ACCESS", "false");
        withEnv("PASSWORD_ACCESS", "false");
        withEnv("USER_NAME", "user");
        addExposedPort(2222);

        waitingFor(new HostPortWaitStrategy());
    }

    private String encode(PublicKey publicKey) {
        try {
            return "ssh-rsa " +
                    Base64.getEncoder().encodeToString(encodePublicKey(createKey(publicKey.getEncoded())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
