/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package test.encoding;

import junit.framework.TestCase;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.configuration.SimpleProvider;
import org.apache.axis.handlers.soap.SOAPService;
import org.apache.axis.providers.java.RPCProvider;
import org.apache.axis.server.AxisServer;

import javax.xml.namespace.QName;

/**
 * Port of upstream's axis-war XssTest (CVE-2018-8032) to the 1.4 ant test
 * suite: the same getVersion-xss.xml request is sent to the Version service
 * in-process instead of over HTTP to a deployed war.
 */
public class TestNamespaceURIEncoding extends TestCase {

    private static final String XSS_REQUEST =
          "<soapenv:Envelope\n"
        + "    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
        + "    xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n"
        + "    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
        + "    xmlns:axis=\"http://axis.apache.org&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x22;&#x3e;&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x78;&#x6d;&#x6c;&#x6e;&#x73;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3a;&#x2f;&#x2f;&#x77;&#x77;&#x77;&#x2e;&#x77;&#x33;&#x2e;&#x6f;&#x72;&#x67;&#x2f;&#x31;&#x39;&#x39;&#x39;&#x2f;&#x78;&#x68;&#x74;&#x6d;&#x6c;&#x22;&#x3e;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x48;&#x65;&#x6c;&#x6c;&#x6f;&#x27;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;\">\n"
        + "  <soapenv:Body>\n"
        + "    <axis:getVersion soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"/>\n"
        + "  </soapenv:Body>\n"
        + "</soapenv:Envelope>\n";

    public TestNamespaceURIEncoding(String name) {
        super(name);
    }

    public void testGetVersion() throws Exception {
        SimpleProvider provider = new SimpleProvider();
        SOAPService version = new SOAPService(new RPCProvider());
        version.setOption("className", "org.apache.axis.Version");
        version.setOption("allowedMethods", "getVersion");
        provider.deployService(new QName(null, "Version"), version);
        AxisServer engine = new AxisServer(provider);
        engine.init();

        MessageContext msgContext = new MessageContext(engine);
        msgContext.setTargetService("Version");
        msgContext.setRequestMessage(new Message(XSS_REQUEST));
        engine.invoke(msgContext);

        String response = msgContext.getResponseMessage().getSOAPPartAsString();
        assertTrue("response should carry the version: " + response,
                   response.indexOf("getVersionReturn") != -1);
        assertTrue("namespace URI must be encoded in the response: " + response,
                   response.indexOf("<script") == -1);
    }
}
