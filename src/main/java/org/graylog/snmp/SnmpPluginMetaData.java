package org.graylog.snmp;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class SnmpPluginMetaData implements PluginMetaData {
    @Override
    public String getUniqueId() {
        return "org.graylog.snmp.SnmpPlugin";
    }

    @Override
    public String getName() {
        return "SNMP Plugin";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc.";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.graylog.org/");
    }

    @Override
    public Version getVersion() {
        return new Version(0, 4, 0);
    }

    @Override
    public String getDescription() {
        return "SNMP plugins";
    }

    @Override
    public Version getRequiredVersion() {
        return new Version(2, 0, 0);
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
