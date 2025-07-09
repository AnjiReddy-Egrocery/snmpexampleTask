package com.dst.task;

import androidx.appcompat.app.AppCompatActivity;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class MainActivity extends AppCompatActivity {
    private EditText edtUsername, edtAuthProtocol, edtAuthPassword,
            edtPrivacyProtocol, edtPrivacyPassword, edtIpAddress, edtPortNumber;
    private TextView txtSnmpResult;
    private Button btnSnmpGet;
    String Hi;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        edtUsername = findViewById(R.id.edt_userName);
        edtAuthProtocol = findViewById(R.id.edt_authprotocal);
        edtAuthPassword = findViewById(R.id.edt_authpassword);
        edtPrivacyProtocol = findViewById(R.id.edt_privacyprotocaol);
        edtPrivacyPassword = findViewById(R.id.edt_privacypassword);
        edtIpAddress = findViewById(R.id.edt_ipaddress);
        edtPortNumber = findViewById(R.id.edt_portnumber);
        txtSnmpResult = findViewById(R.id.txtSnmpResult);
        btnSnmpGet = findViewById(R.id.btnSnmpGet);

        btnSnmpGet.setOnClickListener(v -> {
            String username = edtUsername.getText().toString().trim();
            String authProtocol = edtAuthProtocol.getText().toString().trim();
            String authPassword = edtAuthPassword.getText().toString().trim();
            String privProtocol = edtPrivacyProtocol.getText().toString().trim();
            String privPassword = edtPrivacyPassword.getText().toString().trim();
            String ipAddress = edtIpAddress.getText().toString().trim();
            String port = edtPortNumber.getText().toString().trim();

            if (username.isEmpty() || authProtocol.isEmpty() || authPassword.isEmpty() ||
                    privProtocol.isEmpty() || privPassword.isEmpty() || ipAddress.isEmpty() || port.isEmpty()) {
                Toast.makeText(this, "Please fill all fields", Toast.LENGTH_SHORT).show();
            } else {
                new SnmpGetTask(username, authProtocol, authPassword, privProtocol, privPassword, ipAddress, port).execute();
            }
        });
    }

    private class SnmpGetTask extends AsyncTask<Void, Void, String> {

        private final String username, authProtocol, authPassword, privProtocol, privPassword, ip, port;

        public SnmpGetTask(String username, String authProtocol, String authPassword,
                           String privProtocol, String privPassword, String ip, String port) {
            this.username = username;
            this.authProtocol = authProtocol.toUpperCase();
            this.authPassword = authPassword;
            this.privProtocol = privProtocol.toUpperCase();
            this.privPassword = privPassword;
            this.ip = ip;
            this.port = port;
        }

        @Override
        protected String doInBackground(Void... voids) {
            try {
                TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
                transport.listen();

                Snmp snmp = new Snmp(transport);
                SecurityProtocols.getInstance().addDefaultProtocols();

                USM usm = new USM(
                        SecurityProtocols.getInstance(),
                        new OctetString(MPv3.createLocalEngineID()),
                        0
                );
                SecurityModels.getInstance().addSecurityModel(usm);

                OID authOID = authProtocol.equals("SHA") ? AuthSHA.ID : AuthMD5.ID;
                OID privOID = privProtocol.equals("AES") ? PrivAES128.ID : PrivDES.ID;

                Log.d("SNMP_DEBUG", "Target: " + ip + ":" + port);
                Log.d("SNMP_DEBUG", "User: " + username + ", Auth: " + authProtocol + ", Priv: " + privProtocol);
                Log.d("SNMP_DEBUG", "Sending SNMP GET request...");


                UsmUser user = new UsmUser(
                        new OctetString(username),
                        authOID,
                        new OctetString(authPassword),
                        privOID,
                        new OctetString(privPassword)
                );

                snmp.getUSM().addUser(new OctetString(username), user);
                snmp.getUSM().setEngineDiscoveryEnabled(true);

                UserTarget target = new UserTarget();
                target.setAddress(GenericAddress.parse("udp:" + ip + "/" + port));
                target.setVersion(SnmpConstants.version3);
                target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
                target.setSecurityName(new OctetString(username));
                target.setRetries(2);
                target.setTimeout(2000);

                ScopedPDU pdu = new ScopedPDU();
                pdu.setType(PDU.GET);
                pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.13712.791.21.1.1.1.3.4.7.0")));

                ResponseEvent event = snmp.send(pdu, target);

                if (event.getResponse() != null) {
                    VariableBinding vb = event.getResponse().get(0);
                    return "Response: " + vb.getOid() + " = " + vb.getVariable();
                } else {
                    return "SNMP Timeout or Error.";
                }

            } catch (Exception e) {
                Log.e("SNMP_ERROR", "Exception: ", e);
                return "Exception: " + e.getMessage();
            }
        }

        @Override
        protected void onPostExecute(String result) {
            txtSnmpResult.setText(result);
        }
    }

}