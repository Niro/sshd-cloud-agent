package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.PublicKeyFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class TestUtils {

    private static final PublicKeyFactory PUBLIC_KEY_FACTORY = new JcaPublicKeyFactory();

    public static String readEnv(String envVariableName) {
        return requireNonNull(System.getenv(envVariableName), "Missing env variable " + envVariableName);
    }

    public static PublicKey readPublicKey(String fileName) {
        String publicKeyPem = new BufferedReader(new InputStreamReader(TestUtils.class.getClassLoader().getResourceAsStream(fileName)))
                .lines()
                .collect(Collectors.joining("\n"));

        return PUBLIC_KEY_FACTORY.create(publicKeyPem);

    }
}
