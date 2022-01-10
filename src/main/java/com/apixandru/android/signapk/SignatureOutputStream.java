package com.apixandru.android.signapk;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

class SignatureOutputStream extends FilterOutputStream {

    private final Signature signature;

    public SignatureOutputStream(OutputStream out, Signature signature) {
        super(out);
        this.signature = signature;
    }

    @Override
    public void write(int b) throws IOException {
        try {
            this.signature.update((byte) b);
        } catch (SignatureException var3) {
            throw new IOException("SignatureException: " + var3);
        }
        super.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        try {
            this.signature.update(b, off, len);
        } catch (SignatureException var5) {
            throw new IOException("SignatureException: " + var5);
        }

        super.write(b, off, len);
    }

}
