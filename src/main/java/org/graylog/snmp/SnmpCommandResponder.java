package org.graylog.snmp;

import com.google.common.collect.Iterables;
import org.graylog.snmp.oid.SnmpMibsLoader;
import org.graylog.snmp.oid.SnmpMibsLoaderRegistry;
import org.graylog.snmp.oid.SnmpOIDDecoder;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;
import org.snmp4j.smi.*;
import org.snmp4j.util.OIDTextFormat;

import java.nio.charset.StandardCharsets;


public class SnmpCommandResponder implements CommandResponder {
    private static final Logger LOG = LoggerFactory.getLogger(SnmpCommandResponder.class);

    private static final String KEY_PREFIX = "snmp_";

    private final RawMessage rawMessage;
    private final OIDTextFormat oidTextFormat;
    private static String securityName;
    private static int securityModel;
    private static int securityLevel;
    private Message message = null;


    public SnmpCommandResponder(
            RawMessage rawMessage,
            SnmpMibsLoaderRegistry mibsLoaderRegistry,
            String mibsPath,
            String securityName,
            Integer securityModel,
            Integer securityLevel){
        this.rawMessage = rawMessage;
        SnmpCommandResponder.securityName = securityName;
        SnmpCommandResponder.securityModel = securityModel;
        SnmpCommandResponder.securityLevel = securityLevel;

        final String inputId = Iterables.getLast(rawMessage.getSourceNodes()).inputId;
        final SnmpMibsLoader mibsLoader = mibsLoaderRegistry.get(inputId);

        if (mibsLoader == null) {
            LOG.info("Initialize new SnmpMibsLoader (custom path: \"{}\")", mibsPath);
            mibsLoaderRegistry.put(inputId, new SnmpMibsLoader(mibsPath));
            this.oidTextFormat = new SnmpOIDDecoder(mibsLoaderRegistry.get(inputId));
        } else {
            this.oidTextFormat = new SnmpOIDDecoder(mibsLoader);
        }
    }

    public Message getMessage() {
        return message;
    }

    private String withKeyPrefix(String key) {
        return KEY_PREFIX + key;
    }

    @Override
    public void processPdu(CommandResponderEvent event) {
        LOG.debug("Processing SNMP event: {}", event);

        final PDU pdu = event.getPDU();
        final Integer32 requestID = pdu.getRequestID();
        /*
          Security models are:
            ANY = 0
            V1 = 1
            V2 = 2
            V3USM = 3
            V3TSM = 4
        */
        if(event.getSecurityModel() < 3) {
            if(SnmpCommandResponder.securityModel == event.getSecurityModel() &&
                    SnmpCommandResponder.securityName.equals(new String(event.getSecurityName(), StandardCharsets.UTF_8))){

            final Message message = new Message("SNMP trap " + requestID.toString(), null, rawMessage.getTimestamp());

            message.addField(withKeyPrefix("trap_type"), PDU.getTypeString(pdu.getType()));
            message.addField(withKeyPrefix("request_id"), requestID.toLong());
            message.addField(withKeyPrefix("security_level"), event.getSecurityLevel());
            message.addField(withKeyPrefix("security_model"), event.getSecurityModel());
            message.addField(withKeyPrefix("security_name"), new String(event.getSecurityName(), StandardCharsets.UTF_8));

            for (final VariableBinding binding : pdu.getVariableBindings()) {
                final String key = decodeOid(binding.getOid());
                final Variable variable = binding.getVariable();

                try {
                    if (variable instanceof TimeTicks) {
                        message.addField(withKeyPrefix(key), ((TimeTicks) variable).toMilliseconds());
                    } else {
                        message.addField(withKeyPrefix(key), variable.toLong());
                    }
                } catch (UnsupportedOperationException e) {
                    message.addField(withKeyPrefix(key), variable.toString());
                }
            }

            this.message = message;
            }
            else {
                LOG.error("Wrong trap community string from {}", rawMessage.getRemoteAddress());
                }
        }
            else if(event.getSecurityModel() >= 3){
            if(SnmpCommandResponder.securityLevel == event.getSecurityLevel()){

                final Message message = new Message("SNMP trap " + requestID.toString(), null, rawMessage.getTimestamp());

                message.addField(withKeyPrefix("trap_type"), PDU.getTypeString(pdu.getType()));
                message.addField(withKeyPrefix("request_id"), requestID.toLong());
                message.addField(withKeyPrefix("msg_proc_model"), event.getMessageProcessingModel());
                message.addField(withKeyPrefix("security_level"), event.getSecurityLevel());
                message.addField(withKeyPrefix("security_model"), event.getSecurityModel());
                message.addField(withKeyPrefix("security_name"), new String(event.getSecurityName(), StandardCharsets.UTF_8));


                for (final VariableBinding binding : pdu.getVariableBindings()) {
                    final String key = decodeOid(binding.getOid());
                    final Variable variable = binding.getVariable();

                    try {
                        if (variable instanceof TimeTicks) {
                            message.addField(withKeyPrefix(key), ((TimeTicks) variable).toMilliseconds());
                        } else {
                            message.addField(withKeyPrefix(key), variable.toLong());
                        }
                    } catch (UnsupportedOperationException e) {
                        message.addField(withKeyPrefix(key), variable.toString());
                    }
                }

                this.message = message;
            }
            else{
                LOG.error("Trap with incorrect security level recieved: {}", event.getSecurityLevel());
                }
        }
        else {
            LOG.error("Cannot determine trap version from message sent by {}", rawMessage.getRemoteAddress());
        }
    }

    private String decodeOid(OID oid) {
        final String decodedOid = oidTextFormat.formatForRoundTrip(oid.getValue());

        if (decodedOid != null) {
            return decodedOid;
        }

        return oid.toDottedString();
    }
}
