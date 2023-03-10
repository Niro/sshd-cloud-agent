package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit.exception;

import com.antonzhdanov.apache.sshd.agent.cloud.exception.CloudSshAgentException;

public class VaultTransitCloudSshAgentException extends CloudSshAgentException {

    public VaultTransitCloudSshAgentException(String message, Throwable cause) {
        super(message, cause);
    }

    public VaultTransitCloudSshAgentException(String message) {
        super(message);
    }
}
