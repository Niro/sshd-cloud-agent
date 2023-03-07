package com.antonzhdanov.apache.sshd.agent.cloud.exception;

public class CloudSshAgentException extends RuntimeException {

    public CloudSshAgentException(String message, Throwable cause) {
        super(message, cause);
    }

    public CloudSshAgentException(String message) {
        super(message);
    }
}
