///*
// * $HeadURL$
// * $Revision$
// * $Date$
// *
// * ====================================================================
// *
// *  Licensed to the Apache Software Foundation (ASF) under one or more
// *  contributor license agreements.  See the NOTICE file distributed with
// *  this work for additional information regarding copyright ownership.
// *  The ASF licenses this file to You under the Apache License, Version 2.0
// *  (the "License"); you may not use this file except in compliance with
// *  the License.  You may obtain a copy of the License at
// *
// *      http://www.apache.org/licenses/LICENSE-2.0
// *
// *  Unless required by applicable law or agreed to in writing, software
// *  distributed under the License is distributed on an "AS IS" BASIS,
// *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// *  See the License for the specific language governing permissions and
// *  limitations under the License.
// * ====================================================================
// *
// * This software consists of voluntary contributions made by many
// * individuals on behalf of the Apache Software Foundation.  For more
// * information on the Apache Software Foundation, please see
// * <http://www.apache.org/>.
// *
// */
//
//package saml20.implementation.security.ssl;
//
//import java.io.IOException;
//import java.net.InetAddress;
//import java.net.InetSocketAddress;
//import java.net.Socket;
//import java.net.SocketAddress;
//import java.net.UnknownHostException;
//import java.security.GeneralSecurityException;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.UnrecoverableKeyException;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.util.Enumeration;
//
//import javax.net.SocketFactory;
//import javax.net.ssl.KeyManager;
//import javax.net.ssl.KeyManagerFactory;
//import javax.net.ssl.SSLContext;
//import javax.net.ssl.TrustManager;
//import javax.net.ssl.TrustManagerFactory;
//import javax.net.ssl.X509TrustManager;
//
//import org.apache.commons.httpclient.ConnectTimeoutException;
//import org.apache.commons.httpclient.params.HttpConnectionParams;
//import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
//
//import com.mendix.core.Core;
//import com.mendix.logging.ILogNode;
//
///**
// * <p>
// * AuthSSLProtocolSocketFactory can be used to validate the identity of the HTTPS 
// * server against a list of trusted certificates and to authenticate to the HTTPS 
// * server using a private key. 
// * </p>
// * 
// * <p>
// * AuthSSLProtocolSocketFactory will enable server authentication when supplied with
// * a {@link KeyStore truststore} file containg one or several trusted certificates. 
// * The client secure socket will reject the connection during the SSL session handshake 
// * if the target HTTPS server attempts to authenticate itself with a non-trusted 
// * certificate.
// * </p>
// * 
// * <p>
// * Use JDK keytool utility to import a trusted certificate and generate a truststore file:    
// *    <pre>
// *     keytool -import -alias "my server cert" -file server.crt -keystore my.truststore
// *    </pre>
// * </p>
// * 
// * <p>
// * AuthSSLProtocolSocketFactory will enable client authentication when supplied with
// * a {@link KeyStore keystore} file containg a private key/public certificate pair. 
// * The client secure socket will use the private key to authenticate itself to the target 
// * HTTPS server during the SSL session handshake if requested to do so by the server. 
// * The target HTTPS server will in its turn verify the certificate presented by the client
// * in order to establish client's authenticity
// * </p>
// * 
// * <p>
// * Use the following sequence of actions to generate a keystore file
// * </p>
// *   <ul>
// *     <li>
// *      <p>
// *      Use JDK keytool utility to generate a new key
// *      <pre>keytool -genkey -v -alias "my client key" -validity 365 -keystore my.keystore</pre>
// *      For simplicity use the same password for the key as that of the keystore
// *      </p>
// *     </li>
// *     <li>
// *      <p>
// *      Issue a certificate signing request (CSR)
// *      <pre>keytool -certreq -alias "my client key" -file mycertreq.csr -keystore my.keystore</pre>
// *     </p>
// *     </li>
// *     <li>
// *      <p>
// *      Send the certificate request to the trusted Certificate Authority for signature. 
// *      One may choose to act as her own CA and sign the certificate request using a PKI 
// *      tool, such as OpenSSL.
// *      </p>
// *     </li>
// *     <li>
// *      <p>
// *       Import the trusted CA root certificate
// *       <pre>keytool -import -alias "my trusted ca" -file caroot.crt -keystore my.keystore</pre> 
// *      </p>
// *     </li>
// *     <li>
// *      <p>
// *       Import the PKCS#7 file containg the complete certificate chain
// *       <pre>keytool -import -alias "my client key" -file mycert.p7 -keystore my.keystore</pre> 
// *      </p>
// *     </li>
// *     <li>
// *      <p>
// *       Verify the content the resultant keystore file
// *       <pre>keytool -list -v -keystore my.keystore</pre> 
// *      </p>
// *     </li>
// *   </ul>
// * <p>
// * Example of using custom protocol socket factory for a specific host:
// *     <pre>
// *     Protocol authhttps = new Protocol("https",  
// *          new AuthSSLProtocolSocketFactory(
// *              new URL("file:my.keystore"), "mypassword",
// *              new URL("file:my.truststore"), "mypassword"), 443); 
// *
// *     HttpClient client = new HttpClient();
// *     client.getHostConfiguration().setHost("localhost", 443, authhttps);
// *     // use relative url only
// *     GetMethod httpget = new GetMethod("/");
// *     client.executeMethod(httpget);
// *     </pre>
// * </p>
// * <p>
// * Example of using custom protocol socket factory per default instead of the standard one:
// *     <pre>
// *     Protocol authhttps = new Protocol("https",  
// *          new AuthSSLProtocolSocketFactory(
// *              new URL("file:my.keystore"), "mypassword",
// *              new URL("file:my.truststore"), "mypassword"), 443); 
// *     Protocol.registerProtocol("https", authhttps);
// *
// *     HttpClient client = new HttpClient();
// *     GetMethod httpget = new GetMethod("https://localhost/");
// *     client.executeMethod(httpget);
// *     </pre>
// * </p>
// * @author <a href="mailto:oleg -at- ural.ru">Oleg Kalnichevski</a>
// * 
// * <p>
// * DISCLAIMER: HttpClient developers DO NOT actively support this component.
// * The component is provided as a reference material, which may be inappropriate
// * for use without additional customization.
// * </p>
// */
//
//public class AuthSSLProtocolSocketFactory implements SecureProtocolSocketFactory {
//
//    /** Log object for this class. */
//    private static final ILogNode logNode = Core.getLogger("AuthSSLProtocolSocketFactory");
//
//	private String keystorePassword;
//    private KeyStore keystore = null;
//    private KeyStore truststore = null;
//    private SSLContext sslcontext = null;
//
//
//    /**
//     * Constructor for AuthSSLProtocolSocketFactory. Either a keystore or truststore file
//     * must be given. Otherwise SSL context initialization error will result.
//     * 
//     * @param keyStore URL of the keystore file. May be <tt>null</tt> if HTTPS client
//     *        authentication is not to be used.
//     * @param keystorePassword Password to unlock the keystore. IMPORTANT: this implementation
//     *        assumes that the same password is used to protect the key and the keystore itself.
//     * @param keyStore2 URL of the truststore file. May be <tt>null</tt> if HTTPS server
//     *        authentication is not to be used.
//     * @param truststorePassword Password to unlock the truststore.
//     */
//    public AuthSSLProtocolSocketFactory(
//        final KeyStore keyStore, final String keystorePassword, 
//        final KeyStore trustStore)
//    {
//        super();
//        this.keystore = keyStore;
//        this.keystorePassword = keystorePassword;
//        this.truststore = trustStore;
//    }
//
//    private static KeyManager[] createKeyManagers(final KeyStore keystore, final String password)
//        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException 
//    {
//        if (keystore == null) {
//            throw new IllegalArgumentException("Keystore may not be null");
//        }
//        logNode.debug("Initializing key manager");
//        KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(
//            KeyManagerFactory.getDefaultAlgorithm());
//        kmfactory.init(keystore, password != null ? password.toCharArray(): null);
//        return kmfactory.getKeyManagers(); 
//    }
//
//    private static TrustManager[] createTrustManagers(final KeyStore keystore)
//        throws KeyStoreException, NoSuchAlgorithmException
//    { 
//        if (keystore == null) {
//            throw new IllegalArgumentException("Keystore may not be null");
//        }
//        logNode.debug("Initializing trust manager");
//        TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(
//            TrustManagerFactory.getDefaultAlgorithm());
//        tmfactory.init(keystore);
//        
//        TrustManager[] trustmanagers = tmfactory.getTrustManagers();
//        for (int i = 0; i < trustmanagers.length; i++) {
//            if (trustmanagers[i] instanceof X509TrustManager) {
//                trustmanagers[i] = new AuthSSLX509TrustManager(
//                    (X509TrustManager)trustmanagers[i]); 
//            }
//        }
//        return trustmanagers; 
//    }
//
//    private SSLContext createSSLContext() {
//        try {
//            KeyManager[] keymanagers = null;
//            TrustManager[] trustmanagers = null;
//            if (this.keystore != null) {
//                if (logNode.isDebugEnabled()) {
//                    Enumeration<?> aliases = this.keystore.aliases();
//                    while (aliases.hasMoreElements()) {
//                        String alias = (String)aliases.nextElement();                        
//                        Certificate[] certs = this.keystore.getCertificateChain(alias);
//                        if (certs != null) {
//                        	if( logNode.isDebugEnabled() ) {
//                        		logNode.debug("Certificate chain '" + alias + "':");
//	                            for (int c = 0; c < certs.length; c++) {
//	                                if (certs[c] instanceof X509Certificate) {
//	                                    X509Certificate cert = (X509Certificate)certs[c];
//	                                    logNode.debug(" Certificate " + (c + 1) + ":");
//	                                    logNode.debug("  Subject DN: " + cert.getSubjectDN());
//	                                    logNode.debug("  Signature Algorithm: " + cert.getSigAlgName());
//	                                    logNode.debug("  Valid from: " + cert.getNotBefore() );
//	                                    logNode.debug("  Valid until: " + cert.getNotAfter());
//	                                    logNode.debug("  Issuer: " + cert.getIssuerDN());
//	                                }
//	                            }
//                        	}
//                        }
//                    }
//                }
//                keymanagers = createKeyManagers(this.keystore, this.keystorePassword);
//            }
//            if (this.truststore != null) {
//                if (logNode.isDebugEnabled()) {
//                    Enumeration<?> aliases = this.truststore.aliases();
//                    while (aliases.hasMoreElements()) {
//                        String alias = (String)aliases.nextElement();
//                        logNode.debug("Trusted certificate '" + alias + "':");
//                        Certificate trustedcert = this.truststore.getCertificate(alias);
//                        if (trustedcert != null && trustedcert instanceof X509Certificate) {
//                            X509Certificate cert = (X509Certificate)trustedcert;
//                            logNode.debug("  Subject DN: " + cert.getSubjectDN());
//                            logNode.debug("  Signature Algorithm: " + cert.getSigAlgName());
//                            logNode.debug("  Valid from: " + cert.getNotBefore() );
//                            logNode.debug("  Valid until: " + cert.getNotAfter());
//                            logNode.debug("  Issuer: " + cert.getIssuerDN());
//                        }
//                    }
//                }
//                trustmanagers = createTrustManagers(this.truststore);
//            }
//            SSLContext sslcontext = SSLContext.getInstance("SSL");
//            sslcontext.init(keymanagers, trustmanagers, null);
//            return sslcontext;
//        } catch (NoSuchAlgorithmException e) {
//            logNode.error(e.getMessage(), e);
//            throw new AuthSSLInitializationError("Unsupported algorithm exception: " + e.getMessage());
//        } catch (KeyStoreException e) {
//            logNode.error(e.getMessage(), e);
//            throw new AuthSSLInitializationError("Keystore exception: " + e.getMessage());
//        } catch (GeneralSecurityException e) {
//            logNode.error(e.getMessage(), e);
//            throw new AuthSSLInitializationError("Key management exception: " + e.getMessage());
//        }
//    }
//
//    private SSLContext getSSLContext() {
//        if (this.sslcontext == null) {
//            this.sslcontext = createSSLContext();
//        }
//        return this.sslcontext;
//    }
//
//    /**
//     * Attempts to get a new socket connection to the given host within the given time limit.
//     * <p>
//     * To circumvent the limitations of older JREs that do not support connect timeout a 
//     * controller thread is executed. The controller thread attempts to create a new socket 
//     * within the given limit of time. If socket constructor does not return until the 
//     * timeout expires, the controller terminates and throws an {@link ConnectTimeoutException}
//     * </p>
//     *  
//     * @param host the host name/IP
//     * @param port the port on the host
//     * @param clientHost the local host name/IP to bind the socket to
//     * @param clientPort the port on the local machine
//     * @param params {@link HttpConnectionParams Http connection parameters}
//     * 
//     * @return Socket a new socket
//     * 
//     * @throws IOException if an I/O error occurs while creating the socket
//     * @throws UnknownHostException if the IP address of the host cannot be
//     * determined
//     */
//    @Override
//	public Socket createSocket(
//        final String host,
//        final int port,
//        final InetAddress localAddress,
//        final int localPort,
//        final HttpConnectionParams params
//    ) throws IOException, UnknownHostException, ConnectTimeoutException {
//        if (params == null) {
//            throw new IllegalArgumentException("Parameters may not be null");
//        }
//        int timeout = params.getConnectionTimeout();
//        SocketFactory socketfactory = getSSLContext().getSocketFactory();
//        if (timeout == 0) {
//            return socketfactory.createSocket(host, port, localAddress, localPort);
//        } else {
//            Socket socket = socketfactory.createSocket();
//            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
//            SocketAddress remoteaddr = new InetSocketAddress(host, port);
//            socket.bind(localaddr);
//            socket.connect(remoteaddr, timeout);
//            return socket;
//        }
//    }
//
//    /**
//     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
//     */
//    @Override
//	public Socket createSocket(
//        String host,
//        int port,
//        InetAddress clientHost,
//        int clientPort)
//        throws IOException, UnknownHostException
//   {
//       return getSSLContext().getSocketFactory().createSocket(
//            host,
//            port,
//            clientHost,
//            clientPort
//        );
//    }
//
//    /**
//     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
//     */
//    @Override
//	public Socket createSocket(String host, int port)
//        throws IOException, UnknownHostException
//    {
//        return getSSLContext().getSocketFactory().createSocket(
//            host,
//            port
//        );
//    }
//
//    /**
//     * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
//     */
//    @Override
//	public Socket createSocket(
//        Socket socket,
//        String host,
//        int port,
//        boolean autoClose)
//        throws IOException, UnknownHostException
//    {
//        return getSSLContext().getSocketFactory().createSocket(
//            socket,
//            host,
//            port,
//            autoClose
//        );
//    }
//    
//    public static class AuthSSLInitializationError extends RuntimeException {
//		private static final long serialVersionUID = 5196600723621245167L;
//		public AuthSSLInitializationError(String reason) {
//			super(reason);
//		}
//    	public AuthSSLInitializationError(Throwable cause) {
//    		super(cause);
//		}
//    	public AuthSSLInitializationError(String message, Throwable cause) {
//    		super(message, cause);
//		}
//    	
//    }
//}