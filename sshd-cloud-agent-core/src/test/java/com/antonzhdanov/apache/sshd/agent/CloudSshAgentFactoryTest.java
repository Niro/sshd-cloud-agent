package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import lombok.SneakyThrows;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@Test
@SuppressWarnings("unchecked")
public class CloudSshAgentFactoryTest {

    public void testEmptyChannelForwardingFactories() {
        // GIVEN
        CloudSshAgentFactory<CloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(mock(CloudSshAgentProvider.class));

        // WHEN
        List<ChannelFactory> channelForwardingFactories = sshAgentFactory.getChannelForwardingFactories(mock(FactoryManager.class));

        // THEN
        assertTrue(channelForwardingFactories.isEmpty());
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testThatCreateServerIsNotSupported() {
        // GIVEN
        CloudSshAgentFactory<CloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(mock(CloudSshAgentProvider.class));

        // WHEN
        sshAgentFactory.createServer(mock(ConnectionService.class));

        // THEN exception is thrown
    }

    @Test(expectedExceptions = Exception.class)
    public void testThatClientIsNotCreated() {
        // GIVEN
        CloudSshAgentFactory<CloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(mock(CloudSshAgentProvider.class));

        // WHEN
        sshAgentFactory.createClient(mock(Session.class), mock(FactoryManager.class));

        // THEN exception is thrown
    }

    public void testThatClientIsCreated() {
        // GIVEN
        CloudSshAgentProvider sshAgentProvider = mock(CloudSshAgentProvider.class);
        CloudSshAgentFactory<CloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(sshAgentProvider);
        Session session = mock(Session.class);
        CloudKeyInfo keyInfo = mock(CloudKeyInfo.class);
        sshAgentFactory.withKeyInfo(session, keyInfo);

        when(sshAgentProvider.create(eq(session), eq(keyInfo))).thenReturn(mock(CloudSshAgent.class));

        // WHEN
        SshAgent sshAgent = sshAgentFactory.createClient(session, mock(FactoryManager.class));

        // THEN
        assertNotNull(sshAgent);
        verify(sshAgentProvider, times(1)).create(eq(session), eq(keyInfo));
        verifyNoMoreInteractions(sshAgentProvider);
    }

    public void testThatSessionRemoved() {
        // GIVEN
        Session session = mock(Session.class);
        CloudKeyInfo cloudKeyInfo = mock(CloudKeyInfo.class);
        CloudSshAgentFactory<CloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(mock(CloudSshAgentProvider.class));
        Map<Session, CloudKeyInfo> keyInfosPerSession = getFieldValue(sshAgentFactory, "keyInfosPerSession");

        // WHEN
        try (var unused = sshAgentFactory.withKeyInfo(session, cloudKeyInfo)) {
            assertTrue(keyInfosPerSession.containsKey(session));
            assertEquals(keyInfosPerSession.get(session), cloudKeyInfo);
        }

        // THEN
        assertFalse(keyInfosPerSession.containsKey(session));
    }

    @SneakyThrows
    public <T> T getFieldValue(Object object, String fieldName) {
        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        Object value = field.get(object);
        field.setAccessible(false);

        return (T) value;
    }
}