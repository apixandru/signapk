package com.apixandru.android.signapk;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;
import java.util.jar.*;
import java.util.zip.ZipEntry;

class SignApk {

    private static X509Certificate readPublicKey(File file) throws IOException, GeneralSecurityException {
        try (FileInputStream input = new FileInputStream(file)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(input);
        }
    }

    private static String readPassword(File keyFile) {
        System.out.print("Enter password for " + keyFile + " (password will not be hidden): ");
        System.out.flush();
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));

        try {
            return stdin.readLine();
        } catch (IOException ex) {
            return null;
        }
    }

    private static KeySpec decryptPrivateKey(byte[] encryptedPrivateKey, File keyFile) throws GeneralSecurityException {
        EncryptedPrivateKeyInfo epkInfo;
        try {
            epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
        } catch (IOException ex) {
            return null;
        }

        char[] password = readPassword(keyFile).toCharArray();
        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));
        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(2, key, epkInfo.getAlgParameters());

        try {
            return epkInfo.getKeySpec(cipher);
        } catch (InvalidKeySpecException ex) {
            System.err.println("signapk: Password for " + keyFile + " may be bad.");
            throw ex;
        }
    }

    private static PrivateKey readPrivateKey(File file) throws IOException, GeneralSecurityException {
        try (DataInputStream input = new DataInputStream(new FileInputStream(file))) {
            byte[] bytes = new byte[(int) file.length()];
            input.read(bytes);

            KeySpec spec = decryptPrivateKey(bytes, file);
            if (spec == null) {
                spec = new PKCS8EncodedKeySpec(bytes);
            }

            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (InvalidKeySpecException ex) {
                return KeyFactory.getInstance("DSA").generatePrivate(spec);
            }
        }
    }

    private static Manifest addDigestsToManifest(JarFile jar) throws IOException, GeneralSecurityException {
        Manifest input = jar.getManifest();
        Manifest output = new Manifest();
        Attributes main = output.getMainAttributes();
        if (input != null) {
            main.putAll(input.getMainAttributes());
        } else {
            main.putValue("Manifest-Version", "1.0");
            main.putValue("Created-By", "1.0 (Android SignApk)");
        }

        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] buffer = new byte[4096];
        Enumeration<JarEntry> e = jar.entries();

        while (true) {
            String name;
            JarEntry entry;
            do {
                do {
                    if (!e.hasMoreElements()) {
                        return output;
                    }

                    entry = e.nextElement();
                    name = entry.getName();
                } while (entry.isDirectory());
            } while (name.equals("META-INF/MANIFEST.MF"));

            InputStream data = jar.getInputStream(entry);

            int num;
            while ((num = data.read(buffer)) > 0) {
                md.update(buffer, 0, num);
            }

            Attributes attr = null;
            if (input != null) {
                attr = input.getAttributes(name);
            }

            attr = attr != null ? new Attributes(attr) : new Attributes();
            attr.putValue("SHA1-Digest", encodeBase64(md));
            output.getEntries().put(name, attr);
        }
    }

    private static String encodeBase64(MessageDigest md) {
        return Base64.getEncoder()
                .encodeToString(md.digest());
    }

    private static void writeSignatureFile(Manifest manifest, OutputStream out) throws IOException, GeneralSecurityException {
        Manifest sf = new Manifest();
        Map<String, Attributes> attributes = sf.getEntries();
        Attributes main = sf.getMainAttributes();
        main.putValue("Signature-Version", "1.0");
        main.putValue("Created-By", "1.0 (Android SignApk)");
        MessageDigest md = MessageDigest.getInstance("SHA1");
        PrintStream print = new PrintStream(new DigestOutputStream(new ByteArrayOutputStream(), md), true, "UTF-8");
        manifest.write(print);
        print.flush();
        main.putValue("SHA1-Digest-Manifest", encodeBase64(md));
        Map<String, Attributes> entries = manifest.getEntries();

        for (Entry<String, Attributes> entry : entries.entrySet()) {
            print.print("Name: " + entry.getKey() + "\r\n");

            for (Entry<Object, Object> attributeEntry : entry.getValue().entrySet()) {
                print.print(attributeEntry.getKey() + ": " + attributeEntry.getValue() + "\r\n");
            }

            print.print("\r\n");
            print.flush();
            Attributes sfAttr = new Attributes();
            sfAttr.putValue("SHA1-Digest", encodeBase64(md));
            attributes.put(entry.getKey(), sfAttr);
        }

        sf.write(out);
    }

    private static void writeSignatureBlock(Signature signature, X509Certificate publicKey, OutputStream out) throws IOException, GeneralSecurityException {
        AlgorithmId sha1 = AlgorithmId.get("SHA1");
        AlgorithmId rsa = AlgorithmId.get("RSA");
        X500Name issuerName = new X500Name(publicKey.getIssuerX500Principal().getName());
        SignerInfo signerInfo = new SignerInfo(issuerName, publicKey.getSerialNumber(), sha1, rsa, signature.sign());
        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[]{sha1}, new ContentInfo(ContentInfo.DATA_OID, null), new X509Certificate[]{publicKey}, new SignerInfo[]{signerInfo});
        pkcs7.encodeSignedData(out);
    }

    private static void copyFiles(Manifest manifest, JarFile in, JarOutputStream out) throws IOException {
        byte[] buffer = new byte[4096];
        Map<String, Attributes> entries = manifest.getEntries();

        for (String name : entries.keySet()) {
            JarEntry inEntry = in.getJarEntry(name);
            if (inEntry.getMethod() == ZipEntry.STORED) {
                out.putNextEntry(new JarEntry(inEntry));
            } else {
                out.putNextEntry(new JarEntry(name));
            }
            InputStream data = in.getInputStream(inEntry);
            int num;
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
            }
            out.flush();
        }
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        if (args.length != 4) {
            System.err.println("Usage: signapk publickey.x509[.pem] privatekey.pk8 input.jar output.jar");
            System.exit(2);
        }

        X509Certificate publicKey = readPublicKey(new File(args[0]));
        PrivateKey privateKey = readPrivateKey(new File(args[1]));

        try (JarFile inputJar = new JarFile(new File(args[2]), false);
             JarOutputStream outputJar = new JarOutputStream(new FileOutputStream(args[3]))) {
            outputJar.setLevel(9);

            Manifest manifest = addDigestsToManifest(inputJar);
            Map<String, Attributes> manifestEntries = manifest.getEntries();
            manifestEntries.remove("META-INF/CERT.SF");
            manifestEntries.remove("META-INF/CERT.RSA");
            outputJar.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
            manifest.write(outputJar);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            outputJar.putNextEntry(new JarEntry("META-INF/CERT.SF"));
            writeSignatureFile(manifest, new SignatureOutputStream(outputJar, signature));
            outputJar.putNextEntry(new JarEntry("META-INF/CERT.RSA"));
            writeSignatureBlock(signature, publicKey, outputJar);
            copyFiles(manifest, inputJar, outputJar);
        }
    }

}
