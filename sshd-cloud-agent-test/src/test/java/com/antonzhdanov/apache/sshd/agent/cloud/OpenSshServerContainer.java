package com.antonzhdanov.apache.sshd.agent.cloud;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SSHNamedCurves;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

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

        start();
    }

    private String encode(PublicKey publicKey) {
        try {
            String prefix = null;
            AsymmetricKeyParameter cipherParameters = PublicKeyFactory.createKey(publicKey.getEncoded());

            if (publicKey instanceof RSAPublicKey) {
                prefix = "ssh-rsa";
            } else if (publicKey instanceof ECPublicKey) {
                prefix = "ecdsa-sha2-" + SSHNamedCurves.getNameForParameters(((ECPublicKeyParameters) cipherParameters).getParameters());
            } else {
                throw new UnsupportedOperationException(publicKey.getClass().getCanonicalName());
            }

            return prefix + " " +
                    Base64.getEncoder().encodeToString(OpenSSHPublicKeyUtil.encodePublicKey(cipherParameters));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
