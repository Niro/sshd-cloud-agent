package com.antonzhdanov.apache.sshd.agent.cloud.exception;

import org.apache.sshd.common.SshException;

public class CloudSshAgentException extends SshException {

    public CloudSshAgentException(String message, Throwable cause) {
        super(message, cause);
    }

    public CloudSshAgentException(String message) {
        super(message);
    }
}
