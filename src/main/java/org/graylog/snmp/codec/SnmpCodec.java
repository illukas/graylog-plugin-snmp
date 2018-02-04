package org.graylog.snmp.codec;

import com.google.common.collect.ImmutableMap;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;
import org.graylog.snmp.SnmpCommandResponder;
import org.graylog.snmp.oid.SnmpMibsLoaderRegistry;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.transports.NettyTransport;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.TransportStateReference;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.DummyTransport;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Objects;

@Codec(name = "snmp", displayName = "SNMP")
public class SnmpCodec extends AbstractCodec {
    private static final Logger LOG = LoggerFactory.getLogger(SnmpCodec.class);

    private static final String CK_MIBS_PATH = "mibs_path";
    private static final String CK_SECURITY_NAME = "community";
    private static final String CK_SECURITY_MODEL = "security_model";
    private static final String CK_SECURITY_LEVEL = "security_level";
    private static final String CK_USER_NAME = "user_name";
    private static final String CK_AUTH_PASS = "auth_pass";
    private static final String CK_PRIV_PASS = "priv_pass";
    private static final String CK_AUTH_PROTO = "auth_protocol";
    private static final String CK_PRIV_PROTO = "priv_protocol";

    private final SnmpMibsLoaderRegistry mibsLoaderRegistry;
    private final String mibsPath;
    private final String securityName;
    private final int securityModel;
    private final int securityLevel;
    private final String userName;
    private final String authPass;
    private final String privPass;
    private final String authProto;
    private final String privProto;

    private static final Map<String, String> SECURITY_MODEL = ImmutableMap.of(
            "1", "v1",
            "2", "v2c",
            "3", "v3"
    );
    private static final Map<String, String> SECURITY_LEVEL = ImmutableMap.of(
            "1", "noauthnopriv",
            "2", "authnopriv",
            "3", "authpriv"
    );
    private static final Map<String, String> AUTH_PROTO = ImmutableMap.of(
            "1", "MD5",
            "2", "SHA"
    );
    private static final Map<String, String> PRIV_PROTO = ImmutableMap.of(
            "1", "DES",
            "2", "AES128",
            "3", "AES192",
            "4", "AES256"
    );

    @AssistedInject
    protected SnmpCodec(@Assisted Configuration configuration,
                                  SnmpMibsLoaderRegistry mibsLoaderRegistry){
        super(configuration);
        this.mibsPath = configuration.getString(CK_MIBS_PATH);
        this.mibsLoaderRegistry = mibsLoaderRegistry;
        this.securityName = configuration.getString(CK_SECURITY_NAME);
        this.securityModel = Integer.parseInt(Objects.requireNonNull(configuration.getString(CK_SECURITY_MODEL)));
        this.securityLevel = Integer.parseInt(Objects.requireNonNull(configuration.getString(CK_SECURITY_LEVEL)));
        this.userName = configuration.getString(CK_USER_NAME);
        this.authPass = configuration.getString(CK_AUTH_PASS);
        this.privPass = configuration.getString(CK_PRIV_PASS);
        this.authProto = configuration.getString(CK_AUTH_PROTO);
        this.privProto = configuration.getString(CK_PRIV_PROTO);
        }


    @Nullable
    @Override
    public Message decode(@Nonnull RawMessage rawMessage) {
        try {
            final MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
            final SnmpCommandResponder responder = new SnmpCommandResponder(
                    rawMessage,
                    mibsLoaderRegistry,
                    mibsPath,
                    securityName,
                    securityModel,
                    securityLevel);

            final USM usm = new USM(SecurityProtocols.getInstance().addDefaultProtocols(),
                            new OctetString(MPv3.createLocalEngineID()), 0);
            usm.setEngineDiscoveryEnabled(true);
            final OctetString securityNameOS = new OctetString(securityName);


            messageDispatcher.addCommandResponder(responder);
            switch(securityModel){
                case 1 : {
                    messageDispatcher.addMessageProcessingModel(new MPv1());
                    break;
                }
                case 2 : {
                    messageDispatcher.addMessageProcessingModel(new MPv2c());
                    break;
                }
                case 3 : {
                    messageDispatcher.addMessageProcessingModel(new MPv3(usm));
                    SecurityModels.getInstance().addSecurityModel(usm);

                    //Here we convert configuration fields from Strings to OctetStreams, because USM doesn't like Strings.

                    OctetString userNameOS = new OctetString(userName);
                    OctetString authPassOS = new OctetString(authPass);
                    OctetString privPassOS = new OctetString(privPass);
                    OID authProtoOID = new OID();
                    OID privProtoOID = new OID();

                    if(authProto.equals("2")){
                        authProtoOID = new OID(AuthSHA.ID);
                    } else if(authProto.equals("1")){
                        authProtoOID = new OID(AuthMD5.ID);
                    }
                    switch (privProto) {
                        case "1" :   {
                            privProtoOID = new OID(PrivDES.ID);
                            break;
                        }
                        case "2": {
                            privProtoOID = new OID(PrivAES128.ID);
                            break;
                        }
                        case "3": {
                            privProtoOID = new OID(PrivAES192.ID);
                            break;
                        }
                        case "4": {
                            privProtoOID = new OID(PrivAES256.ID);
                            break;
                        }
                    }
                    usm.addUser(securityNameOS, new UsmUser(userNameOS, authProtoOID, authPassOS, privProtoOID, privPassOS));
                    break;
                }
            }


            final IpAddress ipAddress = new IpAddress(Objects.requireNonNull(rawMessage.getRemoteAddress()).getAddress());
            final DummyTransport<IpAddress> transport = new DummyTransport<>(ipAddress);

            messageDispatcher.processMessage(
                    transport,
                    ipAddress,
                    ByteBuffer.wrap(rawMessage.getPayload()),
                    new TransportStateReference(transport, ipAddress, securityNameOS, SecurityLevel.get(securityLevel), SecurityLevel.get(securityLevel), false, null)
                    );


            return responder.getMessage();
        } catch (Exception e) {
            LOG.error("Unable to decode SNMP packet", e);
            return null;
        }
    }

    @FactoryClass
    public interface Factory extends AbstractCodec.Factory<SnmpCodec> {
        @Override
        SnmpCodec create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest cr = super.getRequestedConfiguration();
            cr.addField(
                    new TextField(
                            CK_MIBS_PATH,
                            "MIBs Path",
                            "",
                            "Custom MIBs load path in addition to the system defaults: /usr/share/mibs, /usr/share/snmp/mibs",
                            ConfigurationField.Optional.OPTIONAL
                    )
            );
            cr.addField(
                    new TextField(
                            CK_SECURITY_NAME,
                            "Community",
                            "public",
                            "V1/V2c: Community string as configured on the device sending traps"
                    )
            );
            cr.addField(
                    new DropdownField(
                            CK_SECURITY_MODEL,
                            "Version",
                            "v2c",
                            SECURITY_MODEL,
                            "SNMP Trap security model for this input",
                            ConfigurationField.Optional.NOT_OPTIONAL
                    )
            );
            cr.addField(
                    new DropdownField(
                            CK_SECURITY_LEVEL,
                            "Security Level",
                            "1",
                            SECURITY_LEVEL,
                            "V3: Required security level to receive traps on this input.",
                            ConfigurationField.Optional.OPTIONAL
                    )
            );
            cr.addField(
                    new TextField(
                            CK_USER_NAME,
                            "User Name",
                            "User Name",
                            "V3: User Name to authenticate the trap sender",
                            ConfigurationField.Optional.OPTIONAL
                    )
            );
            cr.addField(
                    new TextField(
                            CK_AUTH_PASS,
                           "Authentication Password",
                           "Auth Pass",
                           "V3: Password for authenticating the user name of the trap sender",
                            ConfigurationField.Optional.OPTIONAL,
                            TextField.Attribute.IS_PASSWORD
                    )
            );
            cr.addField(
                    new DropdownField(
                            CK_AUTH_PROTO,
                            "Authentication Protocol",
                            "SHA",
                            AUTH_PROTO,
                            "V3: Authentication hashing algorithm used by trap sender",
                            ConfigurationField.Optional.OPTIONAL
                    )
            );
            cr.addField(
                    new TextField(
                            CK_PRIV_PASS,
                           "Privacy Password",
                           "Priv Pass",
                           "V3: Password for decrypting the trap",
                            ConfigurationField.Optional.OPTIONAL,
                            TextField.Attribute.IS_PASSWORD
                    )
            );
            cr.addField(
                    new DropdownField(
                            CK_PRIV_PROTO,
                            "Privacy Protocol",
                            "AES128",
                            PRIV_PROTO,
                            "V3: Protocol used to decrypt the trap",
                            ConfigurationField.Optional.OPTIONAL
                    )
            );
            return cr;
        }
        @Override
        public void overrideDefaultValues(@Nonnull ConfigurationRequest cr) {
            super.overrideDefaultValues(cr);

            if (cr.containsField(NettyTransport.CK_PORT)) {
                cr.getField(NettyTransport.CK_PORT).setDefaultValue(1620);
            }
        }
    }

}

