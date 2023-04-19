package com.fsck.k9.ECDSA;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;

public class ECDSA {

    public ECPublicKeyParameters publicKey;
    public ECPrivateKeyParameters privateKey;
    public ECDomainParameters domainParams;
    BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    BigInteger gx = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    BigInteger gy = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    BigInteger cofactor = new BigInteger("0000000000000000000000000000000000000000000000000000000000000001", 16);

    public ECDSA(){
        Security.addProvider(new BouncyCastleProvider());

        ECCurve curve = new ECCurve.Fp(p,a,b);
        ECPoint generator = curve.createPoint(gx, gy);

        ECDomainParameters domainParams = new ECDomainParameters(
            curve,
            generator,
            order,
            cofactor
        );
        this.domainParams = domainParams;
    }

    public void generateKey(){
        // Generate a private key
        SecureRandom random = new SecureRandom();
        BigInteger d;
        do {
            d = new BigInteger(order.bitLength(), random);
        } while (d.compareTo(BigInteger.ZERO) <= 0 || d.compareTo(order) >= 0);

        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(
            d,
            this.domainParams
        );

        this.privateKey = privateKey;

        ECPoint publicKeyPoint = domainParams.getG().multiply(privateKey.getD());
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(publicKeyPoint, domainParams);

        this.publicKey = publicKey;
    }

    public BigInteger[] createSignature(String message){
        // Hash message using keccak
        byte[] messageBytes = message.getBytes();
        keccak keccak = new keccak();
        byte[] hash = keccak.kec(messageBytes);

        // Sign the hash using ECDSA
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privateKey);
        BigInteger[] signature = signer.generateSignature(hash);

        return signature;
    }

    public boolean verifySignature(BigInteger[] signature, String message){
        // Hash message using keccak
        byte[] messageBytes = message.getBytes();
        keccak keccak = new keccak();
        byte[] hash = keccak.kec(messageBytes);

        // Verify signature
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKey);
        boolean verified = signer.verifySignature(hash, signature[0], signature[1]);
        return verified;
    }

    public void setPrivateKey(BigInteger d){
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(
            d,
            this.domainParams
        );
        this.privateKey = privateKey;
    }

    public void setPublicKey(BigInteger x, BigInteger y){
        ECCurve curve = new ECCurve.Fp(p,a,b);
        ECPoint point = curve.createPoint(x, y);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
            point,
            this.domainParams
        );
        this.publicKey = publicKey;
    }

    public static void main(String[] args) {
        String myString = "qwertyuiopasdfghjklzxcvbnm";
        ECDSA ecc = new ECDSA();
        ecc.generateKey();
        BigInteger[] signature = ecc.createSignature(myString);
        boolean verified = ecc.verifySignature(signature, myString);
        System.out.println("Private Key: " + ecc.privateKey.getD().toString()); //get Private Key
        // System.out.println("Public Key: " + ecc.publicKey.getQ().toString());
        System.out.println("Public Key: (" + ecc.publicKey.getQ().getXCoord().toString() + "," + ecc.publicKey.getQ().getYCoord().toString() + ")");
        System.out.println("Signature (r): " + signature[0].toString(16));
        System.out.println("Signature (s): " + signature[1].toString(16));
        System.out.println("Verified: " + verified);

        ecc.setPrivateKey(ecc.privateKey.getD());
        ecc.setPublicKey(ecc.publicKey.getQ().getXCoord().toBigInteger(), ecc.publicKey.getQ().getYCoord().toBigInteger());
        signature = ecc.createSignature(myString);
        verified = ecc.verifySignature(signature, myString);
        System.out.println("Private Key: " + ecc.privateKey.getD().toString()); //get Private Key
        // System.out.println("Public Key: " + ecc.publicKey.getQ().toString());
        System.out.println("Public Key: (" + ecc.publicKey.getQ().getXCoord().toString() + "," + ecc.publicKey.getQ().getYCoord().toString() + ")");
        System.out.println("Signature (r): " + signature[0].toString(16));
        System.out.println("Signature (s): " + signature[1].toString(16));
        System.out.println("Verified: " + verified);
    }
}

// ini keccakny pake keccak.java aja
class keccak {
    static long[] RC = new long[]{
        0x0000000000000001L,
        0x0000000000008082L,
        0x800000000000808aL,
        0x8000000080008000L,
        0x000000000000808bL,
        0x0000000080000001L,
        0x8000000080008081L,
        0x8000000000008009L,
        0x000000000000008aL,
        0x0000000000000088L,
        0x0000000080008009L,
        0x000000008000000aL,
        0x000000008000808bL,
        0x800000000000008bL,
        0x8000000000008089L,
        0x8000000000008003L,
        0x8000000000008002L,
        0x8000000000000080L,
        0x000000000000800aL,
        0x800000008000000aL,
        0x8000000080008081L,
        0x8000000000008080L,
        0x0000000080000001L,
        0x8000000080008008L
    };

    public static long rot(long a, int n) {
        return (a << (n % 64)) | (a >>> (64-(n % 64)));
    }

    public static long[][] theta(long[][] state) {
        long[] C = new long[5];
        for (int i = 0; i < 5; i++) {
            C[i] = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ^ state[i][4];
        }
        long[] D = new long[5];
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ rot(C[(i + 1) % 5], 1);
        }
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++){
                state[i][j] = state[i][j] ^ D[i];
            }
        }
        return state;
    }

    public static long[][] rhoPi(long[][] state) {
        int i = 1, j = 0;
        long current = state[i][j];
        for (int t = 0; t < 24; t++) {
            int temp = i;
            i = j;
            j = (2 * temp + 3 * j) % 5;
            long temp2 = state[i][j];
            state[i][j] = rot(current, (t + 1) * (t + 2) / 2);
            current = temp2;
        }
        return state;
    }

    public static long[][] chi(long[][] state) {
        long[][] newState = new long[5][5];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                newState[i][j] = state[i][j] ^ ((~state[(i + 1) % 5][j]) & state[(i + 2) % 5][j]);
            }
        }
        return newState;
    }

    public static long[][] iota(long[][] state, int i) {
        state[0][0] = state[0][0] ^ RC[i];
        return state;
    }

    public static long[][] round(long[][] state) {
        // long R = 1L;
        for (int i = 0; i < 24; i++){
            state = theta(state);
            state = rhoPi(state);
            state = chi(state);
            state = iota(state, i);
        }
        return state;
    }

    public static long toLane(byte[] a, int i) {
        long lane = 0;
        for (int j = 0; j < 8; j++) {
            lane |= ((long) (a[i + j] & 0xFF)) << (8 * j);
        }
        return lane;
    }

    public static byte[] toByte(long a) {
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte)(a >> (8*i));
        }
        return result;
    }

    public static byte[] permutation(byte[] state) {
        long[][] lanes = new long[5][5];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                lanes[i][j] = toLane(state, 8 * (i + 5 * j));
            }
        }
        lanes = round(lanes);
        byte[] newState = new byte[200];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                byte[] laneBytes = toByte(lanes[x][y]);
                for (int i = 0; i < 8; i++) {
                    newState[8 * (x + 5 * y) + i] = laneBytes[i];
                }
            }
        }
        return newState;
    }

    public byte[] kec(byte[] inputBytes) {
        byte[] state = new byte[200];
        int rateInBytes = 1088 / 8;
        int digestInBytes = 256 / 8;
        int blockSize = 0;
        int inputOffset = 0;

        while (inputOffset < inputBytes.length) {
            blockSize = Math.min(inputBytes.length - inputOffset, rateInBytes);
            for (int i = 0; i < blockSize; i++) {
                state[i] ^= inputBytes[i + inputOffset];
            }
            inputOffset += blockSize;
            if (blockSize == rateInBytes) {
                state = permutation(state);
                blockSize = 0;
            }
        }

        state[blockSize] ^= 0x01;
        state[rateInBytes - 1] ^= 0x80;
        state = permutation(state);


        byte[] outputBytes = new byte[digestInBytes];
        int outputOffset = 0;
        while (outputOffset < digestInBytes) {
            int bytesToCopy = Math.min(rateInBytes, digestInBytes - outputOffset);
            System.arraycopy(state, 0, outputBytes, outputOffset, bytesToCopy);
            outputOffset += bytesToCopy;
            if (outputOffset < digestInBytes) {
                state = permutation(state);
            }
        }
        return outputBytes;
    }

    // public static void main(String[] args) {
    //     String myString = "qwertyuiopasdfghjklzxcvbnm";
    //     byte[] myBytes = myString.getBytes(StandardCharsets.UTF_8);
    //     byte[] x = kec(1088, 512, myBytes, 256);
    //     for (byte f : x) {
    //         System.out.print(String.format("%02x", f));
    //     }
    // }
}
