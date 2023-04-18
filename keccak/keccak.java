import java.nio.charset.StandardCharsets;

public class keccak {
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

    public static byte[] kec(int r, int c, byte[] inputBytes, int d) {
        byte[] state = new byte[200];
        int rateInBytes = r / 8;
        int digestInBytes = d / 8;
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

    public static void main(String[] args) {
        String myString = "qwertyuiopasdfghjklzxcvbnm";
        byte[] myBytes = myString.getBytes(StandardCharsets.UTF_8);
        byte[] x = kec(1088, 512, myBytes, 256);
        for (byte f : x) {
            System.out.print(String.format("%02x", f));
        }
    }
}