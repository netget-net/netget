/*
 * Ss7Peer: test glue over Restcomm jSS7 8.0.112, used by NetGet's SS7/SIGTRAN tests as an
 * independent SS7 peer.
 *
 * Everything on the wire -- SCTP (or TCP) transport, M3UA ASP/AS management and DATA, SCCP UDT,
 * TCAP dialogues and components, MAP and CAP operations, the ISUP numbers inside CAP and the SMS
 * TPDUs inside MAP -- is encoded and decoded by jSS7. This file only wires jSS7's stacks together
 * the way jSS7's own map-load example does (NettySctpManagementImpl -> M3UAManagementImpl ->
 * SccpStackImpl -> TCAPStackImpl -> MAPStackImpl / CAPStackImpl), picks the operations to send,
 * and prints what came back. NetGet shares no code with it.
 *
 * Arguments are key=value pairs (see usage() below). Output protocol, one line per event on
 * stdout, space separated key=value pairs:
 *
 *   READY                         the M3UA AS is ACTIVE; traffic can flow
 *   RESULT scenario=<s> ...       originate: the scenario's operation succeeded
 *   ERROR scenario=<s> code=<n>   originate: the peer answered with a MAP/CAP error
 *   ABORT scenario=<s> reason=..  originate: the dialogue was aborted or refused
 *   REJECT scenario=<s> problem=  originate: the peer (or TCAP locally) rejected the component
 *   TIMEOUT scenario=<s>          originate: nothing conclusive within timeout_secs
 *   CAP scenario=idp op=<op> ...  originate: one per CAP operation the gsmSCF sent
 *   FAIL ...                      a local failure (bad arguments, stack never became ready)
 *   DONE results=<n>              originate: last line
 *   RECV op=<op> ...              answer: one per operation received, decoded
 *   SENT op=<op> ...              answer: what the CAP gsmSCF answered with
 *   DONE dialogues=<n>            answer: last line
 *
 * Line shapes, field by field:
 *   RESULT scenario=sri-sm imsi=<digits> nnn=<digits> lmsi=<hex|none>
 *   RESULT scenario=ati state=<assumedIdle|camelBusy|notProvidedFromVLR|netDetNotReachable:<reason>|none>
 *          vlr=<digits|none> age=<int|none> cgi=<mcc 3 digits>-<mnc 2 digits>-<lac decimal>-<ci decimal>|none
 *   RESULT scenario=ussd dcs=<int> text=<pct>
 *   RESULT scenario=mo-fsm|mt-fsm ok=true rp_ui=<hex of a returned SM-RP-UI|none>
 *   RESULT scenario=idp ops=<op,op,...|none> ended=<end|abort|timeout>
 *   CAP scenario=idp op=connect dest=<digits> | op=releaseCall cause=<int>
 *          | op=requestReportBCSMEvent events=<eventType:monitorMode,...> | op=<other CAP op>
 *   RECV op=sri-sm msisdn= sc= pri=      RECV op=ati msisdn=|imsi= gsmscf=
 *   RECV op=ussd dcs= text=<pct> msisdn=
 *   RECV op=mo-fsm|mt-fsm da= oa= tpdu=submit to=<digits> text=<pct> | tpdu=deliver from=<digits> text=<pct>
 *   RECV op=idp service_key= called= calling= event= imsi= msc= called_bcd=
 *   RECV op=eventReportBCSM event= leg= type=   (idp_arm=true only)
 *   SENT op=connect dest=31677777777 | op=releaseCall cause=21|16 | op=requestReportBCSMEvent events=.. | op=continue
 *
 * Exit status: originate 0 when every scenario printed a terminal line, 1 otherwise, 3 when the
 * AS never became ACTIVE; answer 0, or 2 when max_dialogues was given and not reached in time;
 * 64 bad arguments; 70 a stack failure.
 *
 * Values never contain spaces. Free text (USSD strings, SMS text) is percent-encoded UTF-8
 * (RFC 3986 style: java.net.URLEncoder, with its '+' for space rewritten to %20), so any
 * percent-decoder restores it exactly. Absent optional fields print as "none". Address-like
 * values are digit strings; SM-RP-DA/OA print as imsi:<digits>, msisdn:<digits>, sc:<digits> or
 * lmsi:<hex>.
 *
 * Behaviour of jSS7 worth knowing when pointing it at another implementation:
 *   - m3ua=as waits for NTFY(AS-ACTIVE) after ASPAC-ACK before it calls the AS active (and so
 *     before READY); m3ua=ipsp-client does not. An AS against an IPSP-server peer never gets READY.
 *   - A server association only accepts the exact remote IP:PORT given; the client must bind it.
 *     A client association retries its connect every second until the server is up.
 *   - The ussd dialogue carries MAP-OpenInfo (originating reference = local GT, destination
 *     reference = MSISDN): jSS7 refuses a networkUnstructuredSsContext TC-BEGIN without it.
 *
 * stdout carries only those lines: System.out is redirected to stderr before jSS7 is touched, and
 * log4j logs to stderr at WARN (override with log_level=DEBUG|INFO|WARN|ERROR|OFF).
 */

import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import org.mobicents.protocols.ss7.cap.CAPStackImpl;
import org.mobicents.protocols.ss7.cap.api.CAPApplicationContext;
import org.mobicents.protocols.ss7.cap.api.CAPDialog;
import org.mobicents.protocols.ss7.cap.api.CAPDialogListener;
import org.mobicents.protocols.ss7.cap.api.CAPParameterFactory;
import org.mobicents.protocols.ss7.cap.api.CAPProvider;
import org.mobicents.protocols.ss7.cap.api.errors.CAPErrorMessage;
import org.mobicents.protocols.ss7.cap.api.isup.CalledPartyNumberCap;
import org.mobicents.protocols.ss7.cap.api.isup.CauseCap;
import org.mobicents.protocols.ss7.cap.api.primitives.BCSMEvent;
import org.mobicents.protocols.ss7.cap.api.primitives.CalledPartyBCDNumber;
import org.mobicents.protocols.ss7.cap.api.primitives.EventTypeBCSM;
import org.mobicents.protocols.ss7.cap.api.primitives.MonitorMode;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.CAPDialogCircuitSwitchedCall;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.CAPServiceCircuitSwitchedCallListener;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.CircuitSwitchedCallMessage;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.ConnectRequest;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.EventReportBCSMRequest;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.InitialDPRequest;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.ReleaseCallRequest;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.RequestReportBCSMEventRequest;
import org.mobicents.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.DestinationRoutingAddress;
import org.mobicents.protocols.ss7.inap.api.primitives.LegType;
import org.mobicents.protocols.ss7.inap.api.primitives.MiscCallInfoDpAssignment;
import org.mobicents.protocols.ss7.inap.api.primitives.MiscCallInfoMessageType;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.isup.ISUPParameterFactory;
import org.mobicents.protocols.ss7.isup.message.parameter.CalledPartyNumber;
import org.mobicents.protocols.ss7.isup.message.parameter.CallingPartyNumber;
import org.mobicents.protocols.ss7.isup.message.parameter.CauseIndicators;
import org.mobicents.protocols.ss7.isup.message.parameter.NAINumber;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.M3UAManagementEventListener;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPParameterFactory;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.primitives.SubscriberIdentity;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPDialogMobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformation;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberInfo;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberState;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberStateChoice;
import org.mobicents.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPDialogSms;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPServiceSmsListener;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPServiceSupplementaryListener;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.smstpdu.NumberingPlanIdentification;
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsDeliverTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsSubmitTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.TypeOfNumber;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserData;
import org.mobicents.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.mobicents.protocols.ss7.map.smstpdu.AbsoluteTimeStampImpl;
import org.mobicents.protocols.ss7.map.smstpdu.AddressFieldImpl;
import org.mobicents.protocols.ss7.map.smstpdu.DataCodingSchemeImpl;
import org.mobicents.protocols.ss7.map.smstpdu.ProtocolIdentifierImpl;
import org.mobicents.protocols.ss7.map.smstpdu.SmsDeliverTpduImpl;
import org.mobicents.protocols.ss7.map.smstpdu.SmsSubmitTpduImpl;
import org.mobicents.protocols.ss7.map.smstpdu.UserDataImpl;
import org.mobicents.protocols.ss7.map.smstpdu.ValidityPeriodImpl;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.mobicents.protocols.ss7.sccp.impl.parameter.BCDOddEncodingScheme;
import org.mobicents.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

public final class Ss7Peer {

    // ------------------------------------------------------------------ output

    /** The real stdout; System.out itself is pointed at stderr so jSS7 cannot write here. */
    private static PrintStream OUT;

    static synchronized void emit(String line) {
        OUT.println(line);
        OUT.flush();
    }

    static void log(String msg) {
        System.err.println("[ss7peer] " + msg);
    }

    /** Percent-encoded UTF-8 with %20 for space, so the value never contains a space. */
    static String enc(String s) {
        if (s == null) {
            return "none";
        }
        try {
            return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        if (b == null) {
            return "none";
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    static String digits(AddressString a) {
        return a == null ? "none" : a.getAddress();
    }

    static String da(SM_RP_DA da) {
        if (da == null) {
            return "none";
        }
        if (da.getIMSI() != null) {
            return "imsi:" + da.getIMSI().getData();
        }
        if (da.getServiceCentreAddressDA() != null) {
            return "sc:" + da.getServiceCentreAddressDA().getAddress();
        }
        if (da.getLMSI() != null) {
            return "lmsi:" + hex(da.getLMSI().getData());
        }
        return "none";
    }

    static String oa(SM_RP_OA oa) {
        if (oa == null) {
            return "none";
        }
        if (oa.getMsisdn() != null) {
            return "msisdn:" + oa.getMsisdn().getAddress();
        }
        if (oa.getServiceCentreAddressOA() != null) {
            return "sc:" + oa.getServiceCentreAddressOA().getAddress();
        }
        return "none";
    }

    static String problem(Problem p) {
        if (p == null) {
            return "none";
        }
        Object specific;
        switch (p.getType()) {
            case General:
                specific = p.getGeneralProblemType();
                break;
            case Invoke:
                specific = p.getInvokeProblemType();
                break;
            case ReturnResult:
                specific = p.getReturnResultProblemType();
                break;
            default:
                specific = p.getReturnErrorProblemType();
                break;
        }
        return p.getType() + ":" + specific;
    }

    /** "onApplyChargingRequest" -> "applyCharging"; "onReleaseCallRequest" -> "releaseCall". */
    static String opName(String method) {
        String s = method.substring(2);
        if (s.endsWith("Request")) {
            s = s.substring(0, s.length() - "Request".length());
        } else if (s.endsWith("Response")) {
            s = s.substring(0, s.length() - "Response".length());
        }
        return Character.toLowerCase(s.charAt(0)) + s.substring(1);
    }

    // ------------------------------------------------------------------ arguments

    private static final Map<String, String> ARGS = new LinkedHashMap<String, String>();

    static String str(String key, String def) {
        String v = ARGS.get(key);
        return v == null || v.isEmpty() ? def : v;
    }

    static int num(String key, int def) {
        String v = ARGS.get(key);
        return v == null || v.isEmpty() ? def : Integer.parseInt(v.trim());
    }

    static String host(String hostPort) {
        return hostPort.substring(0, hostPort.lastIndexOf(':'));
    }

    static int port(String hostPort) {
        return Integer.parseInt(hostPort.substring(hostPort.lastIndexOf(':') + 1));
    }

    static void usage() {
        System.err.println(String.join("\n",
                "usage: java -jar jss7-peer.jar key=value ...",
                "  role=originate|answer              (required)",
                "  transport=sctp|tcp                 (default sctp)",
                "  association=client|server          (default client for originate, server for answer)",
                "  local=IP:PORT remote=IP:PORT       (required; a server association only accepts remote)",
                "  m3ua=as|sgw|ipsp-client|ipsp-server  (default as for originate, sgw for answer)",
                "  opc=N dpc=N ni=N(2) rc=N(absent: no Routing Context) traffic_mode=loadshare|override|broadcast",
                "  local_ssn remote_ssn               (MAP; default 8/6 originate, 6/8 answer)",
                "  cap_local_ssn cap_remote_ssn       (CAP; default 146/146)",
                "  local_gt remote_gt                 (GT0100 digits in the SCCP addresses)",
                "  originate: scenarios=sri-sm,ati,ussd,mo-fsm,mt-fsm,idp timeout_secs=10 ready_timeout_secs=30",
                "    msisdn sc ati_msisdn gsmscf ussd imsi sms_to sms_from sms_text",
                "    service_key called calling msc called_bcd",
                "  answer: max_dialogues=N timeout_secs=N(default 60) idp_arm=false",
                "  log_level=WARN"));
    }

    // ------------------------------------------------------------------ stacks

    private static String role;
    private static int opc;
    private static int dpc;
    private static final ParameterFactoryImpl SCCP_FACTORY = new ParameterFactoryImpl();
    private static final org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl M3UA_FACTORY =
            new org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl();

    private static NettySctpManagementImpl sctp;
    private static M3UAManagementImpl m3ua;
    private static SccpStackImpl sccp;
    private static TCAPStackImpl mapTcap;
    private static TCAPStackImpl capTcap;
    private static MAPStackImpl mapStack;
    private static CAPStackImpl capStack;
    private static MAPProvider map;
    private static CAPProvider cap;
    private static MAPParameterFactory mapf;
    private static CAPParameterFactory capf;

    private static SccpAddress mapLocal;
    private static SccpAddress mapRemote;
    private static SccpAddress capLocal;
    private static SccpAddress capRemote;

    private static final CountDownLatch READY = new CountDownLatch(1);

    static SccpAddress sccpAddress(int pc, int ssn, String gtDigits) {
        // Route on DPC+SSN, with a GT0100 (TT 0, ISDN/telephony, BCD, international) carried
        // alongside it, so no SCCP global title translation rules are needed. The BCD scheme's
        // odd/even flavour must match the digit count or jSS7 drops the last digit.
        GlobalTitle gt = SCCP_FACTORY.createGlobalTitle(gtDigits, 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                gtDigits.length() % 2 == 0 ? BCDEvenEncodingScheme.INSTANCE : BCDOddEncodingScheme.INSTANCE,
                NatureOfAddress.INTERNATIONAL);
        return SCCP_FACTORY.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, gt, pc, ssn);
    }

    static void buildStacks(File persistDir) throws Exception {
        boolean originate = role.equals("originate");
        IpChannelType channel = str("transport", "sctp").equalsIgnoreCase("tcp") ? IpChannelType.TCP : IpChannelType.SCTP;
        String association = str("association", originate ? "client" : "server");
        String local = str("local", null);
        String remote = str("remote", null);
        if (local == null || remote == null) {
            throw new IllegalArgumentException("local=IP:PORT and remote=IP:PORT are required");
        }
        opc = num("opc", originate ? 1 : 2);
        dpc = num("dpc", originate ? 2 : 1);
        int ni = num("ni", 2);
        int localSsn = num("local_ssn", originate ? 8 : 6);
        int remoteSsn = num("remote_ssn", originate ? 6 : 8);
        int capLocalSsn = num("cap_local_ssn", 146);
        int capRemoteSsn = num("cap_remote_ssn", 146);
        String localGt = str("local_gt", originate ? "31600000100" : "31600000200");
        String remoteGt = str("remote_gt", originate ? "31600000200" : "31600000100");

        // --- SCTP / TCP transport
        sctp = new NettySctpManagementImpl("Ss7Peer");
        sctp.setPersistDir(persistDir.getAbsolutePath());
        sctp.start();
        sctp.setConnectDelay(1000);
        sctp.removeAllResourses();
        String assocName = "assoc";
        if (association.equals("server")) {
            sctp.addServer("server", host(local), port(local), channel, false, 0, null);
            sctp.addServerAssociation(host(remote), port(remote), "server", assocName, channel);
            sctp.startServer("server");
        } else if (association.equals("client")) {
            sctp.addAssociation(host(local), port(local), host(remote), port(remote), assocName, channel, null);
        } else {
            throw new IllegalArgumentException("association must be client or server");
        }

        // --- M3UA
        m3ua = new M3UAManagementImpl("Ss7Peer", null);
        m3ua.setPersistDir(persistDir.getAbsolutePath());
        m3ua.setTransportManagement(sctp);
        m3ua.addM3UAManagementEventListener(m3uaListener());
        m3ua.start();
        m3ua.removeAllResourses();

        Functionality functionality;
        IPSPType ipspType = null;
        String mode = str("m3ua", originate ? "as" : "sgw");
        if (mode.equals("as")) {
            functionality = Functionality.AS;
        } else if (mode.equals("sgw")) {
            functionality = Functionality.SGW;
        } else if (mode.equals("ipsp-client")) {
            functionality = Functionality.IPSP;
            ipspType = IPSPType.CLIENT;
        } else if (mode.equals("ipsp-server")) {
            functionality = Functionality.IPSP;
            ipspType = IPSPType.SERVER;
        } else {
            throw new IllegalArgumentException("m3ua must be as, sgw, ipsp-client or ipsp-server");
        }
        RoutingContext rc = str("rc", null) != null ? M3UA_FACTORY.createRoutingContext(new long[] {num("rc", 0)}) : null;
        String tm = str("traffic_mode", "loadshare");
        int tmCode = tm.equals("override") ? TrafficModeType.Override
                : tm.equals("broadcast") ? TrafficModeType.Broadcast : TrafficModeType.Loadshare;
        m3ua.createAs("AS1", functionality, ExchangeType.SE, ipspType, rc, M3UA_FACTORY.createTrafficModeType(tmCode), 1, null);
        m3ua.createAspFactory("ASP1", assocName);
        m3ua.assignAspToAs("AS1", "ASP1");
        m3ua.addRoute(dpc, -1, -1, "AS1");

        // --- SCCP: one MTP3 user part, the remote SPC and both remote SSNs, one SAP + destination
        sccp = new SccpStackImpl("Ss7PeerSccp");
        sccp.setPersistDir(persistDir.getAbsolutePath());
        sccp.setMtp3UserPart(1, m3ua);
        sccp.start();
        sccp.removeAllResourses();
        sccp.getSccpResource().addRemoteSpc(0, dpc, 0, 0);
        sccp.getSccpResource().addRemoteSsn(0, dpc, remoteSsn, 0, false);
        if (capRemoteSsn != remoteSsn) {
            sccp.getSccpResource().addRemoteSsn(1, dpc, capRemoteSsn, 0, false);
        }
        sccp.getRouter().addMtp3ServiceAccessPoint(1, 1, opc, ni, 0);
        sccp.getRouter().addMtp3Destination(1, 1, dpc, dpc, 0, 255, 255);

        mapLocal = sccpAddress(opc, localSsn, localGt);
        mapRemote = sccpAddress(dpc, remoteSsn, remoteGt);
        capLocal = sccpAddress(opc, capLocalSsn, localGt);
        capRemote = sccpAddress(dpc, capRemoteSsn, remoteGt);

        int timeoutMs = num("timeout_secs", originate ? 10 : 60) * 1000;

        // --- TCAP + MAP on the MAP SSN
        mapTcap = new TCAPStackImpl("Ss7PeerTcapMap", sccp.getSccpProvider(), localSsn);
        mapTcap.setPersistDir(persistDir.getAbsolutePath());
        mapTcap.start();
        mapTcap.setDialogIdleTimeout(Math.max(60000, timeoutMs + 5000));
        mapTcap.setInvokeTimeout(originate ? timeoutMs : 30000);
        mapStack = new MAPStackImpl("Ss7PeerMap", mapTcap.getProvider());
        map = mapStack.getMAPProvider();
        mapf = map.getMAPParameterFactory();
        Object mapListener = Proxy.newProxyInstance(Ss7Peer.class.getClassLoader(),
                new Class<?>[] {MAPDialogListener.class, MAPServiceSmsListener.class, MAPServiceMobilityListener.class,
                        MAPServiceSupplementaryListener.class},
                originate ? new MapOriginateHandler() : new MapAnswerHandler());
        map.addMAPDialogListener((MAPDialogListener) mapListener);
        map.getMAPServiceSms().addMAPServiceListener((MAPServiceSmsListener) mapListener);
        map.getMAPServiceMobility().addMAPServiceListener((MAPServiceMobilityListener) mapListener);
        map.getMAPServiceSupplementary().addMAPServiceListener((MAPServiceSupplementaryListener) mapListener);
        map.getMAPServiceSms().acivate();
        map.getMAPServiceMobility().acivate();
        map.getMAPServiceSupplementary().acivate();
        mapStack.start();

        // --- TCAP + CAP on the CAP SSN
        capTcap = new TCAPStackImpl("Ss7PeerTcapCap", sccp.getSccpProvider(), capLocalSsn);
        capTcap.setPersistDir(persistDir.getAbsolutePath());
        capTcap.start();
        capTcap.setDialogIdleTimeout(Math.max(60000, timeoutMs + 5000));
        capTcap.setInvokeTimeout(originate ? timeoutMs : 30000);
        capStack = new CAPStackImpl("Ss7PeerCap", capTcap.getProvider());
        cap = capStack.getCAPProvider();
        capf = cap.getCAPParameterFactory();
        Object capListener = Proxy.newProxyInstance(Ss7Peer.class.getClassLoader(),
                new Class<?>[] {CAPDialogListener.class, CAPServiceCircuitSwitchedCallListener.class},
                originate ? new CapOriginateHandler() : new CapAnswerHandler());
        cap.addCAPDialogListener((CAPDialogListener) capListener);
        cap.getCAPServiceCircuitSwitchedCall().addCAPServiceListener((CAPServiceCircuitSwitchedCallListener) capListener);
        cap.getCAPServiceCircuitSwitchedCall().acivate();
        capStack.start();

        // --- and finally bring the ASP up (ASPUP, ASPAC)
        m3ua.startAsp("ASP1");
        log("stack configured: role=" + role + " " + channel + " " + association + " m3ua=" + mode + " opc=" + opc
                + " dpc=" + dpc + " ni=" + ni + " rc=" + (rc == null ? "none" : num("rc", 0)) + " map_ssn=" + localSsn
                + "->" + remoteSsn + " cap_ssn=" + capLocalSsn + "->" + capRemoteSsn);
    }

    static M3UAManagementEventListener m3uaListener() {
        return (M3UAManagementEventListener) Proxy.newProxyInstance(Ss7Peer.class.getClassLoader(),
                new Class<?>[] {M3UAManagementEventListener.class}, new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        Object basic = objectMethod(proxy, method, args);
                        if (basic != NOT_OBJECT_METHOD) {
                            return basic;
                        }
                        String name = method.getName();
                        if (name.startsWith("onAs") || name.startsWith("onAsp")) {
                            log("m3ua " + name + " " + (args != null && args.length > 0 ? args[0] : ""));
                        }
                        if (name.equals("onAsActive") && READY.getCount() > 0) {
                            READY.countDown();
                            emit("READY");
                        }
                        return null;
                    }
                });
    }

    private static final Object NOT_OBJECT_METHOD = new Object();

    /** equals/hashCode/toString for the listener proxies (jSS7 keeps listeners in lists). */
    static Object objectMethod(Object proxy, Method method, Object[] args) {
        if (method.getDeclaringClass() != Object.class) {
            return NOT_OBJECT_METHOD;
        }
        if (method.getName().equals("equals")) {
            return proxy == args[0];
        }
        if (method.getName().equals("hashCode")) {
            return System.identityHashCode(proxy);
        }
        return "Ss7PeerListener";
    }

    // ------------------------------------------------------------------ originate

    /** One outstanding scenario: the dialogue's user object. */
    static final class Pending {
        final String scenario;
        final CountDownLatch released = new CountDownLatch(1);
        volatile String line;
        // CAP (idp) only
        final List<String> ops = new ArrayList<String>();
        volatile boolean armed;
        volatile boolean reportsSent;
        volatile String ended;
        volatile Object dialog;

        Pending(String scenario) {
            this.scenario = scenario;
        }

        void conclude(String l) {
            if (line == null) {
                line = l;
            }
        }
    }

    /** MAP responses, errors and dialogue events for originated scenarios. */
    static final class MapOriginateHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object basic = objectMethod(proxy, method, args);
            if (basic != NOT_OBJECT_METHOD) {
                return basic;
            }
            String name = method.getName();
            MAPDialog dialog = args != null && args.length > 0 ? dialogOf(args[0]) : null;
            Pending p = dialog == null ? null : (Pending) dialog.getUserObject();
            if (p == null) {
                if (!name.equals("onMAPMessage")) {
                    log("map event without a scenario: " + name);
                }
                return null;
            }
            String s = "scenario=" + p.scenario;
            try {
                if (name.equals("onSendRoutingInfoForSMResponse")) {
                    SendRoutingInfoForSMResponse r = (SendRoutingInfoForSMResponse) args[0];
                    LocationInfoWithLMSI li = r.getLocationInfoWithLMSI();
                    p.conclude("RESULT " + s + " imsi=" + (r.getIMSI() == null ? "none" : r.getIMSI().getData())
                            + " nnn=" + (li == null ? "none" : digits(li.getNetworkNodeNumber()))
                            + " lmsi=" + (li == null || li.getLMSI() == null ? "none" : hex(li.getLMSI().getData())));
                } else if (name.equals("onAnyTimeInterrogationResponse")) {
                    SubscriberInfo si = ((AnyTimeInterrogationResponse) args[0]).getSubscriberInfo();
                    p.conclude("RESULT " + s + " " + describeSubscriberInfo(si));
                } else if (name.equals("onProcessUnstructuredSSResponse")) {
                    ProcessUnstructuredSSResponse r = (ProcessUnstructuredSSResponse) args[0];
                    p.conclude("RESULT " + s + " dcs=" + (r.getDataCodingScheme() == null ? "none" : r.getDataCodingScheme().getCode())
                            + " text=" + (r.getUSSDString() == null ? "none"
                                    : enc(r.getUSSDString().getString(null))));
                } else if (name.equals("onMoForwardShortMessageResponse")) {
                    SmsSignalInfo ui = ((MoForwardShortMessageResponse) args[0]).getSM_RP_UI();
                    p.conclude("RESULT " + s + " ok=true rp_ui=" + (ui == null ? "none" : hex(ui.getData())));
                } else if (name.equals("onMtForwardShortMessageResponse")) {
                    SmsSignalInfo ui = ((MtForwardShortMessageResponse) args[0]).getSM_RP_UI();
                    p.conclude("RESULT " + s + " ok=true rp_ui=" + (ui == null ? "none" : hex(ui.getData())));
                } else if (name.equals("onErrorComponent")) {
                    MAPErrorMessage e = (MAPErrorMessage) args[2];
                    p.conclude("ERROR " + s + " code=" + e.getErrorCode());
                } else if (name.equals("onRejectComponent")) {
                    p.conclude("REJECT " + s + " problem=" + problem((Problem) args[2]) + " local=" + args[3]);
                } else if (name.equals("onInvokeTimeout")) {
                    p.conclude("TIMEOUT " + s);
                } else if (name.equals("onDialogReject")) {
                    p.conclude("ABORT " + s + " reason=refused:" + args[1]);
                } else if (name.equals("onDialogUserAbort")) {
                    p.conclude("ABORT " + s + " reason=user:" + enc(String.valueOf(args[1])));
                } else if (name.equals("onDialogProviderAbort")) {
                    p.conclude("ABORT " + s + " reason=provider:" + args[1] + ":" + args[2]);
                } else if (name.equals("onDialogDelimiter")) {
                    // The peer answered in a TC-CONTINUE. Once we have what we asked for, end it.
                    if (p.line != null) {
                        dialog.close(false);
                    }
                } else if (name.equals("onDialogRelease")) {
                    p.released.countDown();
                } else if (name.endsWith("Request") && args[0] instanceof MAPMessage) {
                    log("unexpected MAP request in scenario " + p.scenario + ": " + name);
                }
            } catch (Throwable t) {
                log("map handler " + name + " failed: " + t);
                p.conclude("ABORT " + s + " reason=local:" + enc(t.getClass().getSimpleName()));
            }
            return null;
        }
    }

    static MAPDialog dialogOf(Object arg) {
        if (arg instanceof MAPDialog) {
            return (MAPDialog) arg;
        }
        if (arg instanceof MAPMessage) {
            return ((MAPMessage) arg).getMAPDialog();
        }
        return null;
    }

    static CAPDialog capDialogOf(Object arg) {
        if (arg instanceof CAPDialog) {
            return (CAPDialog) arg;
        }
        if (arg instanceof CircuitSwitchedCallMessage) {
            return ((CircuitSwitchedCallMessage) arg).getCAPDialog();
        }
        return null;
    }

    static String describeSubscriberInfo(SubscriberInfo si) throws Exception {
        String state = "none";
        String vlr = "none";
        String age = "none";
        String cgi = "none";
        if (si != null) {
            SubscriberState ss = si.getSubscriberState();
            if (ss != null && ss.getSubscriberStateChoice() != null) {
                state = ss.getSubscriberStateChoice().toString();
                if (ss.getSubscriberStateChoice() == SubscriberStateChoice.netDetNotReachable) {
                    state += ":" + ss.getNotReachableReason();
                }
            }
            LocationInformation li = si.getLocationInformation();
            if (li != null) {
                vlr = digits(li.getVlrNumber());
                age = li.getAgeOfLocationInformation() == null ? "none" : li.getAgeOfLocationInformation().toString();
                if (li.getCellGlobalIdOrServiceAreaIdOrLAI() != null
                        && li.getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength() != null) {
                    org.mobicents.protocols.ss7.map.api.primitives.CellGlobalIdOrServiceAreaIdFixedLength c =
                            li.getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength();
                    cgi = String.format("%03d-%02d-%d-%d", c.getMCC(), c.getMNC(), c.getLac(), c.getCellIdOrServiceAreaCode());
                }
            }
        }
        return "state=" + state + " vlr=" + vlr + " age=" + age + " cgi=" + cgi;
    }

    static ISDNAddressString isdn(String digits) {
        return mapf.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, digits);
    }

    static AddressString address(String digits) {
        return mapf.createAddressString(AddressNature.international_number, NumberingPlan.ISDN, digits);
    }

    static MAPApplicationContext mapAc(MAPApplicationContextName name, MAPApplicationContextVersion version) {
        return MAPApplicationContext.getInstance(name, version);
    }

    /** Starts one scenario's dialogue; the returned Pending is its user object. */
    static Pending start(String scenario) throws Exception {
        Pending p = new Pending(scenario);
        String msisdn = str("msisdn", "31628838002");
        String sc = str("sc", "31611111111");
        String smsText = str("sms_text", "Hello from jSS7");
        if (scenario.equals("sri-sm")) {
            MAPDialogSms d = map.getMAPServiceSms().createNewDialog(
                    mapAc(MAPApplicationContextName.shortMsgGatewayContext, MAPApplicationContextVersion.version3),
                    mapLocal, null, mapRemote, null);
            d.setUserObject(p);
            p.dialog = d;
            d.addSendRoutingInfoForSMRequest(isdn(msisdn), true, address(sc), null, false, null, null, null, false, null,
                    false, false, null);
            d.send();
        } else if (scenario.equals("ati")) {
            MAPDialogMobility d = map.getMAPServiceMobility().createNewDialog(
                    mapAc(MAPApplicationContextName.anyTimeEnquiryContext, MAPApplicationContextVersion.version3),
                    mapLocal, null, mapRemote, null);
            d.setUserObject(p);
            p.dialog = d;
            SubscriberIdentity who = mapf.createSubscriberIdentity(isdn(str("ati_msisdn", "31628838002")));
            d.addAnyTimeInterrogationRequest(who, mapf.createRequestedInfo(true, true, null, false, null, false, false, false),
                    isdn(str("gsmscf", "31699999999")), null);
            d.send();
        } else if (scenario.equals("ussd")) {
            // jSS7 refuses a networkUnstructuredSsContext TC-BEGIN without MAP-OpenInfo user
            // information, so this one dialogue carries originating/destination references: the
            // local GT (the MSC) and the subscriber's MSISDN.
            MAPDialogSupplementary d = map.getMAPServiceSupplementary().createNewDialog(
                    mapAc(MAPApplicationContextName.networkUnstructuredSsContext, MAPApplicationContextVersion.version2),
                    mapLocal, address(mapLocal.getGlobalTitle().getDigits()), mapRemote, address(msisdn));
            d.setUserObject(p);
            p.dialog = d;
            CBSDataCodingSchemeImpl dcs = new CBSDataCodingSchemeImpl(0x0F);
            d.addProcessUnstructuredSSRequest(dcs, mapf.createUSSDString(str("ussd", "*100#"), dcs, null), null, isdn(msisdn));
            d.send();
        } else if (scenario.equals("mo-fsm")) {
            MAPDialogSms d = map.getMAPServiceSms().createNewDialog(
                    mapAc(MAPApplicationContextName.shortMsgMORelayContext, MAPApplicationContextVersion.version3),
                    mapLocal, null, mapRemote, null);
            d.setUserObject(p);
            p.dialog = d;
            SmsSubmitTpduImpl submit = new SmsSubmitTpduImpl(false, false, false, 1,
                    new AddressFieldImpl(TypeOfNumber.InternationalNumber, NumberingPlanIdentification.ISDNTelephoneNumberingPlan,
                            str("sms_to", "31622222222")),
                    new ProtocolIdentifierImpl(0), new ValidityPeriodImpl(167),
                    new UserDataImpl(smsText, new DataCodingSchemeImpl(0), null, null));
            SM_RP_OA rpOa = mapf.createSM_RP_OA();
            ((org.mobicents.protocols.ss7.map.service.sms.SM_RP_OAImpl) rpOa).setMsisdn(isdn(msisdn));
            d.addMoForwardShortMessageRequest(mapf.createSM_RP_DA(address(sc)), rpOa, mapf.createSmsSignalInfo(submit, null),
                    null, null);
            d.send();
        } else if (scenario.equals("mt-fsm")) {
            MAPDialogSms d = map.getMAPServiceSms().createNewDialog(
                    mapAc(MAPApplicationContextName.shortMsgMTRelayContext, MAPApplicationContextVersion.version3),
                    mapLocal, null, mapRemote, null);
            d.setUserObject(p);
            p.dialog = d;
            SmsDeliverTpduImpl deliver = new SmsDeliverTpduImpl(false, false, false, false,
                    new AddressFieldImpl(TypeOfNumber.InternationalNumber, NumberingPlanIdentification.ISDNTelephoneNumberingPlan,
                            str("sms_from", "31633333333")),
                    new ProtocolIdentifierImpl(0), new AbsoluteTimeStampImpl(26, 10, 15, 12, 0, 0, 0),
                    new UserDataImpl(smsText, new DataCodingSchemeImpl(0), null, null));
            SM_RP_OA rpOa = mapf.createSM_RP_OA();
            ((org.mobicents.protocols.ss7.map.service.sms.SM_RP_OAImpl) rpOa).setServiceCentreAddressOA(address(sc));
            d.addMtForwardShortMessageRequest(mapf.createSM_RP_DA(mapf.createIMSI(str("imsi", "001010123456789"))), rpOa,
                    mapf.createSmsSignalInfo(deliver, null), false, null);
            d.send();
        } else if (scenario.equals("idp")) {
            CAPDialogCircuitSwitchedCall d = cap.getCAPServiceCircuitSwitchedCall().createNewDialog(
                    CAPApplicationContext.CapV2_gsmSSF_to_gsmSCF, capLocal, capRemote);
            d.setUserObject(p);
            p.dialog = d;
            ISUPParameterFactory isup = cap.getISUPParameterFactory();
            CalledPartyNumber called = isup.createCalledPartyNumber();
            called.setNatureOfAddresIndicator(NAINumber._NAI_INTERNATIONAL_NUMBER);
            called.setNumberingPlanIndicator(CalledPartyNumber._NPI_ISDN);
            called.setInternalNetworkNumberIndicator(CalledPartyNumber._INN_ROUTING_ALLOWED);
            called.setAddress(str("called", "31644444444"));
            CallingPartyNumber calling = isup.createCallingPartyNumber();
            calling.setNatureOfAddresIndicator(NAINumber._NAI_INTERNATIONAL_NUMBER);
            calling.setNumberingPlanIndicator(CallingPartyNumber._NPI_ISDN);
            calling.setAddressRepresentationREstrictedIndicator(CallingPartyNumber._APRI_ALLOWED);
            calling.setScreeningIndicator(CallingPartyNumber._SI_NETWORK_PROVIDED);
            calling.setAddress(str("calling", "31655555555"));
            CalledPartyBCDNumber bcd = ARGS.containsKey("called_bcd")
                    ? capf.createCalledPartyBCDNumber(AddressNature.international_number, NumberingPlan.ISDN, str("called_bcd", ""))
                    : null;
            d.addInitialDPRequest(num("service_key", 100), capf.createCalledPartyNumberCap(called),
                    capf.createCallingPartyNumberCap(calling), null, null, null, null, null, null, null, null, null,
                    EventTypeBCSM.collectedInfo, null, null, null, null, null, null, null, false,
                    mapf.createIMSI(str("imsi", "001010123456789")), null, null, null, null,
                    isdn(str("msc", "31600000003")), bcd, null, false, null);
            d.send();
        } else {
            throw new IllegalArgumentException("unknown scenario " + scenario);
        }
        return p;
    }

    /** gsmSSF side of the idp scenario: prints what the gsmSCF sends and reports armed events. */
    static final class CapOriginateHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object basic = objectMethod(proxy, method, args);
            if (basic != NOT_OBJECT_METHOD) {
                return basic;
            }
            String name = method.getName();
            CAPDialog dialog = args != null && args.length > 0 ? capDialogOf(args[0]) : null;
            Pending p = dialog == null ? null : (Pending) dialog.getUserObject();
            if (p == null) {
                if (!name.equals("onCAPMessage")) {
                    log("cap event without a scenario: " + name);
                }
                return null;
            }
            String s = "scenario=" + p.scenario;
            try {
                if (name.endsWith("Request") && args[0] instanceof CircuitSwitchedCallMessage) {
                    String op = opName(name);
                    p.ops.add(op);
                    StringBuilder line = new StringBuilder("CAP " + s + " op=" + op);
                    if (args[0] instanceof ConnectRequest) {
                        line.append(" dest=").append(destination(((ConnectRequest) args[0]).getDestinationRoutingAddress()));
                    } else if (args[0] instanceof ReleaseCallRequest) {
                        CauseCap c = ((ReleaseCallRequest) args[0]).getCause();
                        line.append(" cause=").append(c == null ? "none" : String.valueOf(c.getCauseIndicators().getCauseValue()));
                    } else if (args[0] instanceof RequestReportBCSMEventRequest) {
                        StringBuilder ev = new StringBuilder();
                        for (BCSMEvent e : ((RequestReportBCSMEventRequest) args[0]).getBCSMEventList()) {
                            ev.append(ev.length() == 0 ? "" : ",").append(e.getEventTypeBCSM()).append(':').append(e.getMonitorMode());
                        }
                        line.append(" events=").append(ev.length() == 0 ? "none" : ev.toString());
                        p.armed = true;
                    }
                    emit(line.toString());
                } else if (name.equals("onErrorComponent")) {
                    CAPErrorMessage e = (CAPErrorMessage) args[2];
                    p.ops.add("error");
                    emit("CAP " + s + " op=error code=" + e.getErrorCode());
                } else if (name.equals("onRejectComponent")) {
                    p.ops.add("reject");
                    emit("CAP " + s + " op=reject problem=" + problem((Problem) args[2]) + " local=" + args[3]);
                } else if (name.equals("onDialogDelimiter")) {
                    // The gsmSCF kept the dialogue open (TC-CONTINUE).
                    if (p.armed && !p.reportsSent) {
                        p.reportsSent = true;
                        CAPDialogCircuitSwitchedCall d = (CAPDialogCircuitSwitchedCall) dialog;
                        d.addEventReportBCSMRequest(EventTypeBCSM.oAnswer, null,
                                capf.createReceivingSideID(LegType.leg2),
                                cap.getINAPParameterFactory().createMiscCallInfo(MiscCallInfoMessageType.notification, null),
                                null);
                        d.send();
                        Thread.sleep(200);
                        CauseIndicators normal = cap.getISUPParameterFactory().createCauseIndicators();
                        normal.setCodingStandard(CauseIndicators._CODING_STANDARD_ITUT);
                        normal.setLocation(CauseIndicators._LOCATION_USER);
                        normal.setCauseValue(16);
                        d.addEventReportBCSMRequest(EventTypeBCSM.oDisconnect,
                                capf.createEventSpecificInformationBCSM(capf.createODisconnectSpecificInfo(capf.createCauseCap(normal))),
                                capf.createReceivingSideID(LegType.leg2),
                                cap.getINAPParameterFactory().createMiscCallInfo(MiscCallInfoMessageType.request, null),
                                null);
                        d.send();
                    } else if (!p.armed || p.reportsSent) {
                        // Nothing armed (or already reported): the SSF has nothing more to say.
                        if (p.ended == null) {
                            p.ended = "end";
                        }
                        dialog.close(false);
                    }
                } else if (name.equals("onDialogClose")) {
                    p.ended = "end";
                } else if (name.equals("onDialogUserAbort") || name.equals("onDialogProviderAbort")) {
                    p.ended = "abort";
                    log("cap " + name + " " + (args.length > 1 ? args[1] : "") + " " + (args.length > 2 ? args[2] : ""));
                } else if (name.equals("onInvokeTimeout")) {
                    log("cap invoke timeout in " + p.scenario);
                } else if (name.equals("onDialogRelease")) {
                    if (p.ended == null) {
                        p.ended = "abort";
                    }
                    p.conclude("RESULT " + s + " ops=" + (p.ops.isEmpty() ? "none" : String.join(",", p.ops)) + " ended=" + p.ended);
                    p.released.countDown();
                }
            } catch (Throwable t) {
                log("cap handler " + name + " failed: " + t);
            }
            return null;
        }
    }

    static String destination(DestinationRoutingAddress dra) throws Exception {
        if (dra == null || dra.getCalledPartyNumber() == null || dra.getCalledPartyNumber().isEmpty()) {
            return "none";
        }
        StringBuilder sb = new StringBuilder();
        for (CalledPartyNumberCap c : dra.getCalledPartyNumber()) {
            sb.append(sb.length() == 0 ? "" : ",").append(c.getCalledPartyNumber().getAddress());
        }
        return sb.toString();
    }

    static int originate() throws Exception {
        int readySecs = num("ready_timeout_secs", 30);
        if (!READY.await(readySecs, TimeUnit.SECONDS)) {
            emit("FAIL reason=not_ready after_secs=" + readySecs);
            emit("DONE results=0");
            return 3;
        }
        // Let SCCP see the MTP-RESUME that accompanies AS-ACTIVE before the first UDT.
        Thread.sleep(num("settle_ms", 500));
        int timeout = num("timeout_secs", 10);
        String[] scenarios = str("scenarios", "sri-sm,ati,ussd,mo-fsm,mt-fsm,idp").split(",");
        int results = 0;
        for (String raw : scenarios) {
            String scenario = raw.trim();
            if (scenario.isEmpty()) {
                continue;
            }
            Pending p;
            try {
                p = start(scenario);
            } catch (Throwable t) {
                log("scenario " + scenario + " could not start: " + t);
                t.printStackTrace();
                emit("FAIL scenario=" + scenario + " reason=" + enc(t.toString()));
                continue;
            }
            boolean released = p.released.await(timeout, TimeUnit.SECONDS);
            if (!released) {
                if (scenario.equals("idp")) {
                    p.line = null;
                    p.conclude("RESULT scenario=idp ops=" + (p.ops.isEmpty() ? "none" : String.join(",", p.ops)) + " ended=timeout");
                } else {
                    p.conclude("TIMEOUT scenario=" + scenario);
                }
                releaseLocally(scenario, p);
            } else if (p.line == null) {
                p.conclude("ABORT scenario=" + scenario + " reason=released_without_answer");
            }
            emit(p.line);
            results++;
        }
        emit("DONE results=" + results);
        return results == countScenarios(scenarios) ? 0 : 1;
    }

    static int countScenarios(String[] scenarios) {
        int n = 0;
        for (String s : scenarios) {
            if (!s.trim().isEmpty()) {
                n++;
            }
        }
        return n;
    }

    /** Frees a dialogue that never concluded, locally and without sending anything more. */
    static void releaseLocally(String scenario, Pending p) {
        try {
            if (p.dialog instanceof MAPDialog) {
                ((MAPDialog) p.dialog).release();
            } else if (p.dialog instanceof CAPDialog) {
                ((CAPDialog) p.dialog).release();
            }
        } catch (Throwable t) {
            log("releasing the " + scenario + " dialogue failed: " + t);
        }
    }

    // ------------------------------------------------------------------ answer

    private static final AtomicInteger DIALOGUES = new AtomicInteger();
    private static final CountDownLatch ANSWER_DONE = new CountDownLatch(1);
    private static int maxDialogues = -1;

    static void dialogueReleased() {
        int n = DIALOGUES.incrementAndGet();
        if (maxDialogues > 0 && n >= maxDialogues) {
            ANSWER_DONE.countDown();
        }
    }

    static String tpduText(UserData ud) throws Exception {
        if (ud == null) {
            return "none";
        }
        ud.decode();
        return enc(ud.getDecodedMessage());
    }

    /** Deterministic HLR / MSC / USSD-gateway answers. */
    static final class MapAnswerHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object basic = objectMethod(proxy, method, args);
            if (basic != NOT_OBJECT_METHOD) {
                return basic;
            }
            String name = method.getName();
            try {
                if (name.equals("onSendRoutingInfoForSMRequest")) {
                    SendRoutingInfoForSMRequest r = (SendRoutingInfoForSMRequest) args[0];
                    String msisdn = digits(r.getMsisdn());
                    emit("RECV op=sri-sm msisdn=" + msisdn + " sc=" + digits(r.getServiceCentreAddress()) + " pri=" + r.getSm_RP_PRI());
                    MAPDialogSms d = r.getMAPDialog();
                    if (msisdn.endsWith("0000")) {
                        d.sendErrorComponent(r.getInvokeId(),
                                map.getMAPErrorMessageFactory().createMAPErrorMessageUnknownSubscriber(null, null));
                    } else {
                        d.addSendRoutingInfoForSMResponse(r.getInvokeId(), mapf.createIMSI("001010123456789"),
                                mapf.createLocationInfoWithLMSI(isdn("31600000001"), null, null, false, null), null, null, null);
                    }
                    d.close(false);
                } else if (name.equals("onAnyTimeInterrogationRequest")) {
                    AnyTimeInterrogationRequest r = (AnyTimeInterrogationRequest) args[0];
                    SubscriberIdentity who = r.getSubscriberIdentity();
                    String id = who == null ? "none"
                            : who.getMSISDN() != null ? "msisdn=" + who.getMSISDN().getAddress()
                                    : who.getIMSI() != null ? "imsi=" + who.getIMSI().getData() : "none";
                    emit("RECV op=ati " + id + " gsmscf=" + digits(r.getGsmSCFAddress()));
                    LocationInformation li = mapf.createLocationInformation(5, null, isdn("31600000002"), null,
                            mapf.createCellGlobalIdOrServiceAreaIdOrLAI(
                                    mapf.createCellGlobalIdOrServiceAreaIdFixedLength(1, 1, 0x1234, 0x5678)),
                            null, null, null, null, false, false, null, null);
                    SubscriberInfo si = mapf.createSubscriberInfo(li,
                            mapf.createSubscriberState(SubscriberStateChoice.assumedIdle, null), null, null, null, null, null,
                            null, null);
                    MAPDialogMobility d = r.getMAPDialog();
                    d.addAnyTimeInterrogationResponse(r.getInvokeId(), si, null);
                    d.close(false);
                } else if (name.equals("onProcessUnstructuredSSRequest")) {
                    ProcessUnstructuredSSRequest r = (ProcessUnstructuredSSRequest) args[0];
                    String text = r.getUSSDString() == null ? null : r.getUSSDString().getString(null);
                    emit("RECV op=ussd dcs=" + (r.getDataCodingScheme() == null ? "none" : r.getDataCodingScheme().getCode())
                            + " text=" + enc(text) + " msisdn=" + digits(r.getMSISDNAddressString()));
                    CBSDataCodingSchemeImpl dcs = new CBSDataCodingSchemeImpl(0x0F);
                    MAPDialogSupplementary d = r.getMAPDialog();
                    d.addProcessUnstructuredSSResponse(r.getInvokeId(), dcs, mapf.createUSSDString("You sent " + text, dcs, null));
                    d.close(false);
                } else if (name.equals("onMoForwardShortMessageRequest")) {
                    MoForwardShortMessageRequest r = (MoForwardShortMessageRequest) args[0];
                    emit("RECV op=mo-fsm da=" + da(r.getSM_RP_DA()) + " oa=" + oa(r.getSM_RP_OA()) + " " + describeTpdu(r.getSM_RP_UI(), true));
                    MAPDialogSms d = r.getMAPDialog();
                    d.addMoForwardShortMessageResponse(r.getInvokeId(), null, null);
                    d.close(false);
                } else if (name.equals("onMtForwardShortMessageRequest")) {
                    MtForwardShortMessageRequest r = (MtForwardShortMessageRequest) args[0];
                    emit("RECV op=mt-fsm da=" + da(r.getSM_RP_DA()) + " oa=" + oa(r.getSM_RP_OA()) + " " + describeTpdu(r.getSM_RP_UI(), false));
                    MAPDialogSms d = r.getMAPDialog();
                    d.addMtForwardShortMessageResponse(r.getInvokeId(), null, null);
                    d.close(false);
                } else if (name.endsWith("Request") && args != null && args[0] instanceof MAPMessage) {
                    MAPMessage m = (MAPMessage) args[0];
                    emit("RECV op=unhandled name=" + opName(name));
                    m.getMAPDialog().close(false);
                } else if (name.equals("onDialogRelease")) {
                    dialogueReleased();
                } else if (name.equals("onDialogUserAbort") || name.equals("onDialogProviderAbort")
                        || name.equals("onRejectComponent") || name.equals("onErrorComponent")) {
                    log("map " + name + " " + (args.length > 1 ? args[1] : "") + " " + (args.length > 2 ? args[2] : ""));
                }
            } catch (Throwable t) {
                log("map answer " + name + " failed: " + t);
                t.printStackTrace();
            }
            return null;
        }
    }

    static String describeTpdu(SmsSignalInfo ui, boolean mobileOriginated) throws Exception {
        if (ui == null) {
            return "tpdu=none";
        }
        SmsTpdu tpdu = ui.decodeTpdu(mobileOriginated);
        if (tpdu instanceof SmsSubmitTpdu) {
            SmsSubmitTpdu t = (SmsSubmitTpdu) tpdu;
            return "tpdu=submit to=" + (t.getDestinationAddress() == null ? "none" : t.getDestinationAddress().getAddressValue())
                    + " text=" + tpduText(t.getUserData());
        }
        if (tpdu instanceof SmsDeliverTpdu) {
            SmsDeliverTpdu t = (SmsDeliverTpdu) tpdu;
            return "tpdu=deliver from=" + (t.getOriginatingAddress() == null ? "none" : t.getOriginatingAddress().getAddressValue())
                    + " text=" + tpduText(t.getUserData());
        }
        return "tpdu=" + tpdu.getSmsTpduType();
    }

    /**
     * gsmSCF side: Connect, or ReleaseCall (cause 21) when the called number ends in 0, in a
     * TC-END. With idp_arm=true it instead arms oAnswer/oDisconnect and sends Continue in a
     * TC-CONTINUE, then answers the oDisconnect report with ReleaseCall (cause 16) in a TC-END.
     */
    static final class CapAnswerHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object basic = objectMethod(proxy, method, args);
            if (basic != NOT_OBJECT_METHOD) {
                return basic;
            }
            String name = method.getName();
            try {
                if (name.equals("onInitialDPRequest")) {
                    InitialDPRequest r = (InitialDPRequest) args[0];
                    String called = r.getCalledPartyNumber() == null ? "none" : r.getCalledPartyNumber().getCalledPartyNumber().getAddress();
                    String calling = r.getCallingPartyNumber() == null ? "none" : r.getCallingPartyNumber().getCallingPartyNumber().getAddress();
                    emit("RECV op=idp service_key=" + r.getServiceKey() + " called=" + called + " calling=" + calling
                            + " event=" + r.getEventTypeBCSM() + " imsi=" + (r.getIMSI() == null ? "none" : r.getIMSI().getData())
                            + " msc=" + digits(r.getMscAddress())
                            + " called_bcd=" + (r.getCalledPartyBCDNumber() == null ? "none" : r.getCalledPartyBCDNumber().getAddress()));
                    CAPDialogCircuitSwitchedCall d = r.getCAPDialog();
                    if (called.endsWith("0")) {
                        CauseIndicators ci = cap.getISUPParameterFactory().createCauseIndicators();
                        ci.setCodingStandard(CauseIndicators._CODING_STANDARD_ITUT);
                        ci.setLocation(CauseIndicators._LOCATION_USER);
                        ci.setCauseValue(21);
                        d.addReleaseCallRequest(capf.createCauseCap(ci));
                        d.close(false);
                        emit("SENT op=releaseCall cause=21");
                    } else if (str("idp_arm", "false").equals("true")) {
                        // Arm oAnswer (notifyAndContinue) and oDisconnect (interrupted) on leg 2 and
                        // let the call continue, keeping the dialogue open with a TC-CONTINUE.
                        ArrayList<BCSMEvent> events = new ArrayList<BCSMEvent>();
                        events.add(capf.createBCSMEvent(EventTypeBCSM.oAnswer, MonitorMode.notifyAndContinue,
                                cap.getINAPParameterFactory().createLegID(true, LegType.leg2), null, false));
                        events.add(capf.createBCSMEvent(EventTypeBCSM.oDisconnect, MonitorMode.interrupted,
                                cap.getINAPParameterFactory().createLegID(true, LegType.leg2), null, false));
                        d.addRequestReportBCSMEventRequest(events, null);
                        d.addContinueRequest();
                        d.send();
                        emit("SENT op=requestReportBCSMEvent events=oAnswer:notifyAndContinue,oDisconnect:interrupted");
                        emit("SENT op=continue");
                    } else {
                        CalledPartyNumber dest = cap.getISUPParameterFactory().createCalledPartyNumber();
                        dest.setNatureOfAddresIndicator(NAINumber._NAI_INTERNATIONAL_NUMBER);
                        dest.setNumberingPlanIndicator(CalledPartyNumber._NPI_ISDN);
                        dest.setInternalNetworkNumberIndicator(CalledPartyNumber._INN_ROUTING_ALLOWED);
                        dest.setAddress("31677777777");
                        ArrayList<CalledPartyNumberCap> list = new ArrayList<CalledPartyNumberCap>();
                        list.add(capf.createCalledPartyNumberCap(dest));
                        d.addConnectRequest(capf.createDestinationRoutingAddress(list), null, null, null, null, null, null, null,
                                null, null, null, null, null, false, false, false, null, false, false);
                        d.close(false);
                        emit("SENT op=connect dest=31677777777");
                    }
                } else if (name.equals("onEventReportBCSMRequest")) {
                    EventReportBCSMRequest r = (EventReportBCSMRequest) args[0];
                    String type = r.getMiscCallInfo() == null ? "none" : String.valueOf(r.getMiscCallInfo().getMessageType());
                    emit("RECV op=eventReportBCSM event=" + r.getEventTypeBCSM() + " leg="
                            + (r.getLegID() == null ? "none" : String.valueOf(r.getLegID().getReceivingSideID())) + " type=" + type);
                    if (r.getEventTypeBCSM() == EventTypeBCSM.oDisconnect) {
                        // An interrupted oDisconnect waits for instructions: release and end.
                        CauseIndicators ci = cap.getISUPParameterFactory().createCauseIndicators();
                        ci.setCodingStandard(CauseIndicators._CODING_STANDARD_ITUT);
                        ci.setLocation(CauseIndicators._LOCATION_USER);
                        ci.setCauseValue(16);
                        r.getCAPDialog().addReleaseCallRequest(capf.createCauseCap(ci));
                        r.getCAPDialog().close(false);
                        emit("SENT op=releaseCall cause=16");
                    }
                } else if (name.endsWith("Request") && args != null && args[0] instanceof CircuitSwitchedCallMessage) {
                    CircuitSwitchedCallMessage m = (CircuitSwitchedCallMessage) args[0];
                    emit("RECV op=" + opName(name));
                    if (m.getCAPDialog() != null) {
                        m.getCAPDialog().close(false);
                    }
                } else if (name.equals("onDialogRelease")) {
                    dialogueReleased();
                } else if (name.equals("onDialogUserAbort") || name.equals("onDialogProviderAbort")
                        || name.equals("onRejectComponent") || name.equals("onErrorComponent")) {
                    log("cap " + name + " " + (args.length > 1 ? args[1] : "") + " " + (args.length > 2 ? args[2] : ""));
                }
            } catch (Throwable t) {
                log("cap answer " + name + " failed: " + t);
                t.printStackTrace();
            }
            return null;
        }
    }

    static int answer() throws Exception {
        maxDialogues = num("max_dialogues", -1);
        int timeout = num("timeout_secs", 60);
        int readySecs = num("ready_timeout_secs", timeout);
        if (READY.await(readySecs, TimeUnit.SECONDS)) {
            // READY was printed by the M3UA listener
        } else {
            log("M3UA AS never became ACTIVE within " + readySecs + "s");
        }
        boolean finished = ANSWER_DONE.await(timeout, TimeUnit.SECONDS);
        // Give the last TC-END a moment to leave before the stack is torn down.
        Thread.sleep(500);
        emit("DONE dialogues=" + DIALOGUES.get());
        if (maxDialogues > 0 && !finished) {
            return 2;
        }
        return 0;
    }

    // ------------------------------------------------------------------ main

    static void configureLogging() {
        Logger root = Logger.getRootLogger();
        root.removeAllAppenders();
        ConsoleAppender appender = new ConsoleAppender(new PatternLayout("%d{HH:mm:ss,SSS} %-5p [%c{1}] %m%n"), "System.err");
        root.addAppender(appender);
        root.setLevel(Level.toLevel(str("log_level", "WARN"), Level.WARN));
    }

    static void deleteRecursively(File f) {
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) {
                deleteRecursively(c);
            }
        }
        f.delete();
    }

    public static void main(String[] argv) throws Exception {
        long t0 = System.currentTimeMillis();
        OUT = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8");
        System.setOut(System.err);

        for (String a : argv) {
            int eq = a.indexOf('=');
            if (eq <= 0) {
                usage();
                emit("FAIL reason=bad_argument arg=" + enc(a));
                System.exit(64);
            }
            ARGS.put(a.substring(0, eq).trim(), a.substring(eq + 1).trim());
        }
        role = str("role", null);
        if (role == null || !(role.equals("originate") || role.equals("answer"))) {
            usage();
            emit("FAIL reason=role_must_be_originate_or_answer");
            System.exit(64);
        }
        configureLogging();

        // jSS7 persists every stack's configuration as XML and reloads it on start. Keep that in a
        // throwaway directory so one run never inherits another's associations or routes.
        final File persistDir = Files.createTempDirectory("ss7peer").toFile();
        System.setProperty("user.dir", persistDir.getAbsolutePath());

        int code;
        try {
            buildStacks(persistDir);
            log("stack started in " + (System.currentTimeMillis() - t0) + " ms since JVM main()");
            code = role.equals("originate") ? originate() : answer();
        } catch (IllegalArgumentException e) {
            usage();
            emit("FAIL reason=" + enc(e.getMessage()));
            code = 64;
        } catch (Throwable t) {
            t.printStackTrace();
            emit("FAIL reason=" + enc(t.toString()));
            code = 70;
        }
        shutdown();
        deleteRecursively(persistDir);
        // Netty and jSS7 leave non-daemon threads behind; do not wait for them.
        Runtime.getRuntime().halt(code);
    }

    static void shutdown() {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (m3ua != null) {
                        m3ua.stopAsp("ASP1");
                    }
                    Thread.sleep(300);
                    if (sctp != null) {
                        sctp.stop();
                    }
                } catch (Throwable ignored) {
                    // best effort
                }
            }
        });
        t.setDaemon(true);
        t.start();
        try {
            t.join(2000);
        } catch (InterruptedException ignored) {
            // best effort
        }
    }
}
