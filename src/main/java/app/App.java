package app;

import java.util.List;
import java.util.Vector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import app.ConfigurationTypes.BulkAlgo;
import app.ConfigurationTypes.Extension;
import app.ConfigurationTypes.KeyExchange;
import app.ConfigurationTypes.KeyExchangeGroup;
import app.ConfigurationTypes.ServerAuth;
import app.ConfigurationTypes.SignatureScheme;
import app.ConfigurationTypes.TlsVersion;
import app.HandshakeStepping.HandshakeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;


public class App {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {  
        /*
        // openssl s_server -cert ./TLS-Core/src/main/resources/certs/rsa2048_rsa_cert.pem -key ./TLS-Core/src/main/resources/certs/rsa2048_key.pem -tls1_2 -Verify 3 -CAfile ./Zusatzzeug/keyGen/rsa2048_cert.pem -trace
        CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
            new BigInteger("22680894355213276814068604237379515326692913667424423179105887452289906651381282343803736135056197131595363416117766447222033440405148554595150495098954618784791409846721078014631997901600818192748951260294724453863786822963457535714201456929910107294028887630816463336166663178044202436591458723765695469483323295740091515251848862253753967572511917223940594872506608243732478287780716299338656301737923256700355562820768458403307832462075060029877854803131864443444034500618089480396072963994147799521776599695622459322293973138939514112920721100797951815691387710738229293066991665386400046197146008454129381303013"),
            new BigInteger("1081220900519306994054118481314527476163106719322647452617727838882406914114781299588271417902671126167388106236144671423388446493562843049877263993876061364494202266642979463380542895308994686679330955004731190982136777534172265998708970859053814947427221608823239751002807226391716969448091277902763492530629102587274894712676589402812658549391491035698540223575850258784236700772902034492790099278379171982874885903225435518252664651224422790750083966520867503120878596752239393242686207324374684442156551897779979099846701806053546967178413553042480432389633260063913612546788291398650159971518641894650833502207"));
        
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/keyGen/rsa2048_cert.pem",
                    privKey
        );
        */

        
        /*
        //EC Certificate
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x04, (byte)0x30, (byte)0xE3, (byte)0x17, (byte)0x0C, (byte)0x60, (byte)0xC7, (byte)0x2E, (byte)0x6F, (byte)0xDD, (byte)0x09, (byte)0x89, (byte)0x5F, (byte)0xAA, (byte)0x26, (byte)0xED, (byte)0x2F, (byte)0x58, (byte)0x72, (byte)0x99, (byte)0xA7, (byte)0xA8, (byte)0x17, (byte)0x0A, (byte)0x2A, (byte)0x6D, (byte)0xED, (byte)0x23, (byte)0x89, (byte)0x84, (byte)0x8A, (byte)0xF7, (byte)0xCB, (byte)0xBF, (byte)0xA8, (byte)0x2C, (byte)0xED, (byte)0x84, (byte)0xBE, (byte)0x99, (byte)0x15, (byte)0xB3, (byte)0xDF, (byte)0x62, (byte)0x93, (byte)0xD5, (byte)0x3D, (byte)0x55, (byte)0xC3, (byte)0x25};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP384R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/keyGen/ec_secp384r1_cert.pem",
                    privKey
        );
        */
        
        
        /*
       //EC Certificate NON-CA
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x04, (byte)0x20, (byte)0xB5, (byte)0xB3, (byte)0xC9, (byte)0x56, (byte)0xE1, (byte)0xD0, (byte)0x3B, (byte)0x20, (byte)0xF9, (byte)0x8D, (byte)0x57, (byte)0x45, (byte)0x50, (byte)0x7E, (byte)0x3F, (byte)0x9F, (byte)0xD2, (byte)0xA4, (byte)0x13, (byte)0x62, (byte)0x90, (byte)0xCF, (byte)0xA0, (byte)0xFA, (byte)0x27, (byte)0x60, (byte)0x0D, (byte)0xF4, (byte)0xC4, (byte)0xD8, (byte)0x4D, (byte)0x14};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP256R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certificates_3/vehicle-controller-ca-cert.pem",
                    privKey
        );
        */

        /*
        // certGen Test
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x04, (byte)0x30, (byte)0xF1, (byte)0xF8, (byte)0x9B, (byte)0x19, (byte)0xA0, (byte)0x96, (byte)0x00, (byte)0x17, (byte)0xAC, (byte)0x27, (byte)0x7B, (byte)0x8D, (byte)0x38, (byte)0xD5, (byte)0x04, (byte)0x2C, (byte)0x33, (byte)0x3B, (byte)0x2B, (byte)0x1B, (byte)0xA2, (byte)0x89, (byte)0xFC, (byte)0xF1, (byte)0xBC, (byte)0x76, (byte)0x1A, (byte)0x3A, (byte)0x42, (byte)0x4F, (byte)0xD1, (byte)0xAE, (byte)0xEF, (byte)0x46, (byte)0xA7, (byte)0x6B, (byte)0xA9, (byte)0xD6, (byte)0x8B, (byte)0xB7, (byte)0x91, (byte)0x18, (byte)0xD4, (byte)0xDA, (byte)0x99, (byte)0x12, (byte)0xFE, (byte)0x57};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP384R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem",
                    privKey
        );
        */

        /*
        // rsa1024_ecdsa
        CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
            new BigInteger("122196060381948061524181822542992910701265350082186396309660022581822502403487504433930918918391270348215377662080919979293352972201341666977666439686093758569559751208961900988053904364482077420392551275507784762644191161672667395076974003605211901879113196745154057490294124316407485242885967672876205342799"),
            new BigInteger("39276439445591588202189451635994105069230428604929374830446745741887651450775352562686037002241666690345254290732480573779917914451703041257374361841212819606453430256634759729697692106919469422720434651742430624650822087125431824981188151317079856307610875006125587845702795210101202837648047020119822006793"));
        
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/rsa1024_ecdsa_cert.pem",
                    privKey
        );
        */

        /*
        // rsa2048_ecdsa
        CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
            new BigInteger("26771365176862042370447575317565893333866273712037299127575052249674034748267894140397512257060726426322455635432866021654806411928200746474640782711282567116925416069973475223851750164467399571358264073882999106033870353964296750679820882007516361140910857888467117716008086392199516237277703953528841565822088283170754234812797697884826276767281787118745219065929293008898620818455193628593075811923553931146948032486881744551681199389494680499733105121735679615830150910409010886912815252815356756220924211463447938426459936019562402757712105879611074030708449744682053450528084497532631901464236091316500928887307"),
            new BigInteger("3817974039482141065587199028115867709003786063590896994001559818905021068628192816015767403308330859569751920237015461058587486901855871903279522645391191442366043628759434917370804017763928011561408290989020723324924382613291721931564549394742689921777367490952559862866313372059947487857486000299942287485742181937280487452268798626155772086785043347656601787917435741531857454522387951048281304351492979192727258718910368045897904523372612560514149153981361480911080238427046988476001823785451736527110241523432142198384633545960663244549097206442975208364759922621377923628888252187350027973877262617888140292365"));
        
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/rsa2048_ecdsa_cert.pem",
                    privKey
        );
        */
        
        /*
        // rsa4096_ecdsa
        CustomRSAPrivateKey privKey = new CustomRSAPrivateKey(
            new BigInteger("870323041865936973091870103424871182443959716636903087203161929732695673467192469840137305410157590635777794004038812230941028770647478622902699349388092891957000194146741038689897422637239853959109045150116847317189612862597164300140707098428531319732688497129471384934739103825184317099441032904973394018922128501436942999910609650854190529492597519888681500945749681544081467994073534483892815358393346326297679661238191200266280874146719754808720501698464357887864408637126065244999084470287095139268633117373092344969781377047751005432558109684456827713722430170410512076538371374490822279219383372064878713103711951158522707707436926438741739605856691652628524008439128450688696386915481675393969896250330155740032457370902372607571413673931454735427967317005185694660040331430176843876172001778177151392497282259670564133082310934455085413383897901946352255292877381725797288866654185154759563197516229643548549782917811488413338485300978536143976580691512568192388965473249455250767063394418400131837077751908111725417818825002736314671611085088959810383091103416945973734155632326348196133136811885315574363476959280793753814055751078215557222129697939318093734512584175738964316827777248132858786686077919868029174323987367"),
            new BigInteger("2016067005899381793360195655310730065091911291559362261961430929738356525387316818111506263977853296311142177753883827246234776301109986137997829010416001862135376305371323695328078644025610908993603009488362565541734268829031032191616178709880963438114838493874267760692348764929521798386130091239212126899579426296947520193444952730410503084949898470086832111623359865076979645368449057736743268482183686069674093627439520129793970497156965277092843672620902454128378965054898956990739077046194182216418204089251534152367314829728637695025016900865132310702948496267608565301563924335211688980616570061519603635427325271229292004846071273115472873906916104883201379322688404647573242493973784636316474451189693690390191209520091234552080511886065342543505774829221086512942759740809418711636705014399692420869582237222292359236578943732827194347784488161331400380928314253895658229795430495824097113205265585771742458547700422870870406209330619630566010364008759233353171735096106044615752719903737584223504654774818164841234680777168146991289547902539238061734424877111718001626976990756893812480642925124010950100842391276437404231840519091618369235260848957358519783916916775301173539676694700818904046314171195175022962433673"));
        
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/rsa4096_ecdsa_cert.pem",
                    privKey
        );
        */

        /*
        // ec_secp256r1_ecdsa_cert
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x80, (byte)0x2D, (byte)0x8C, (byte)0x55, (byte)0xCB, (byte)0x0B, (byte)0xDE, (byte)0x67, (byte)0xE9, (byte)0xE2, (byte)0x9D, (byte)0xF2, (byte)0xAB, (byte)0xA9, (byte)0x60, (byte)0x88, (byte)0x90, (byte)0xBB, (byte)0x35, (byte)0xA8, (byte)0x2A, (byte)0x7B, (byte)0xBB, (byte)0x5F, (byte)0x37, (byte)0x43, (byte)0xD7, (byte)0x93, (byte)0xC0, (byte)0x84, (byte)0x92, (byte)0xC0};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP256R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/ec_secp256r1_ecdsa_cert.pem",
                    privKey
        );
        */

        /*
        // ec_secp384r1_ecdsa_cert
        byte[] derEncdoedPrivKey = new byte[]{(byte)0xF1, (byte)0xF8, (byte)0x9B, (byte)0x19, (byte)0xA0, (byte)0x96, (byte)0x00, (byte)0x17, (byte)0xAC, (byte)0x27, (byte)0x7B, (byte)0x8D, (byte)0x38, (byte)0xD5, (byte)0x04, (byte)0x2C, (byte)0x33, (byte)0x3B, (byte)0x2B, (byte)0x1B, (byte)0xA2, (byte)0x89, (byte)0xFC, (byte)0xF1, (byte)0xBC, (byte)0x76, (byte)0x1A, (byte)0x3A, (byte)0x42, (byte)0x4F, (byte)0xD1, (byte)0xAE, (byte)0xEF, (byte)0x46, (byte)0xA7, (byte)0x6B, (byte)0xA9, (byte)0xD6, (byte)0x8B, (byte)0xB7, (byte)0x91, (byte)0x18, (byte)0xD4, (byte)0xDA, (byte)0x99, (byte)0x12, (byte)0xFE, (byte)0x57};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP384R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/ec_secp384r1_ecdsa_cert.pem",
                    privKey
        );
        */

        /*
        // ec_secp521r1_ecdsa_cert
        byte[] derEncdoedPrivKey = new byte[]{(byte)0x01, (byte)0xD5, (byte)0xC4, (byte)0x9A, (byte)0x07, (byte)0xFA, (byte)0x36, (byte)0x2E, (byte)0x7B, (byte)0x95, (byte)0xB2, (byte)0x24, (byte)0x90, (byte)0x3D, (byte)0x4E, (byte)0x2B, (byte)0x52, (byte)0x77, (byte)0x5E, (byte)0x0E, (byte)0xA3, (byte)0x92, (byte)0xB6, (byte)0x4E, (byte)0x9F, (byte)0x6D, (byte)0xE9, (byte)0xC1, (byte)0x9A, (byte)0xDD, (byte)0x74, (byte)0xCC, (byte)0xC1, (byte)0x45, (byte)0x43, (byte)0x70, (byte)0x1B, (byte)0xFA, (byte)0xBF, (byte)0x40, (byte)0x78, (byte)0x3A, (byte)0x22, (byte)0xC3, (byte)0xA8, (byte)0x9B, (byte)0xF1, (byte)0xC5, (byte)0x1C, (byte)0x93, (byte)0x67, (byte)0x1B, (byte)0x58, (byte)0x04, (byte)0x5B, (byte)0xE4, (byte)0xA4, (byte)0xBB, (byte)0xEC, (byte)0xAD, (byte)0x15, (byte)0x1F, (byte)0x16, (byte)0x99, (byte)0x64, (byte)0x5B};
        CustomECPrivateKey privKey = new CustomECPrivateKey(new BigInteger(derEncdoedPrivKey), NamedGroup.SECP521R1);
        ClientAuthConfig clientAuthConfig = new ClientAuthConfig(
                    "/Users/lth/Library/Mobile Documents/com~apple~CloudDocs/Zweitstudium/Module/00_Masterarbeit/Netzwerk/Bearbeitung/TLS-Attacker/TLS-Attacker/Zusatzzeug/certGen/ec_secp521r1_ecdsa_cert.pem",
                    privKey
        );
        */

        Config myConfig =
            ConfigFactory.getConfig(
                TlsVersion.TLS13,
                KeyExchange.ECDHE,
                KeyExchangeGroup.SECP384R1,
                ServerAuth.ECDSA,
                null,
                new Vector<SignatureScheme>(){{add(SignatureScheme.ECDSA_SHA384);}},
                BulkAlgo.AES_256_GCM_SHA384,
                new Vector<Extension>(){{add(Extension.RESUMPTION_SESSION_TICKET);}});
                //new Vector<>());

        OutboundConnection outboundCon = new OutboundConnection();
        outboundCon.setHostname("localhost");
        outboundCon.setPort(4433);
        myConfig.setDefaultClientConnection(outboundCon);
        
        List<WorkflowTrace> segmentedHandshake = HandshakeStepping.getSegmentedHandshake(HandshakeType.TLS13_WITHOUT_CLIENTAUTH_WITH_RESUMPTION, myConfig, outboundCon);
        Long[][] resultsMeasurement = TimeMeasurement.startTimeMeasurement(null, 1, myConfig, segmentedHandshake, false, 1, 3, 1.5);

        //System.out.println(resultsMeasurement);

        System.out.println("Reached End");
    }

    public static long startTlsClient(Config config, WorkflowTrace trace) {
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        long timeElapsed = 0;
        try {
            long start = System.nanoTime();
            workflowExecutor.executeWorkflow();
            long finish = System.nanoTime();
            timeElapsed = finish - start;
        } catch (WorkflowExecutionException ex) {
            System.out.println(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.warn(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
        }
        return timeElapsed;
    }
}
