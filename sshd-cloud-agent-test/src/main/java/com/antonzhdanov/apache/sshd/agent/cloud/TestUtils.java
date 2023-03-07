package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.PublicKeyFactory;
import lombok.SneakyThrows;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class TestUtils {

    private static final PublicKeyFactory PUBLIC_KEY_FACTORY = new JcaPublicKeyFactory();

    public static String readEnv(String envVariableName) {
        return requireNonNull(System.getenv(envVariableName), "Missing env variable " + envVariableName);
    }

    @SneakyThrows
    public static PublicKey readPublicKey(String fileName) {
        byte[] bytes = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(fileName).toURI()));

        return PUBLIC_KEY_FACTORY.create(new String(bytes));
    }
}
